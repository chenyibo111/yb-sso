package demo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type session struct {
	subject string
	sid     string
	idToken string
	expires time.Time
}

type handler struct {
	clientID      string
	oauth         oauth2.Config
	verifier      *oidc.IDTokenVerifier
	endSessionURL string
	postLogoutURL string
	statusURL     string
	jwksURL       string
	issuer        string
	httpClient    *http.Client
	mu            sync.Mutex
	sessions      map[string]session
}

// New creates one local OIDC client app. Call with port 3100 or 3101.
func New(ctx context.Context, port int) (http.Handler, error) {
	if port != 3100 && port != 3101 {
		return nil, errors.New("demo port must be 3100 or 3101")
	}
	clientID := "demo-a"
	if port == 3101 {
		clientID = "demo-b"
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if dialAddress := os.Getenv("HYDRA_DIAL_ADDRESS"); dialAddress != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "localhost:4444" {
				address = dialAddress
			}
			return dialer.DialContext(ctx, network, address)
		}
		httpClient.Transport = transport
	}
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, "http://localhost:4444/")
	if err != nil {
		return nil, err
	}
	var discovery struct {
		EndSessionURL string `json:"end_session_endpoint"`
		JWKSURL       string `json:"jwks_uri"`
		Issuer        string `json:"issuer"`
	}
	if err := provider.Claims(&discovery); err != nil || discovery.EndSessionURL == "" || discovery.JWKSURL == "" {
		return nil, errors.New("incomplete Hydra discovery")
	}
	statusURL := os.Getenv("SSO_STATUS_URL")
	if statusURL == "" {
		statusURL = "http://localhost:9000/session-status"
	}
	return &handler{
		clientID:      clientID,
		oauth:         oauth2.Config{ClientID: clientID, RedirectURL: "http://localhost:" + strconv.Itoa(port) + "/callback", Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile"}},
		verifier:      provider.Verifier(&oidc.Config{ClientID: clientID}),
		endSessionURL: discovery.EndSessionURL,
		postLogoutURL: "http://localhost:" + strconv.Itoa(port) + "/logged-out",
		statusURL:     statusURL,
		jwksURL:       discovery.JWKSURL,
		issuer:        discovery.Issuer,
		httpClient:    httpClient,
		sessions:      make(map[string]session),
	}, nil
}

func (h *handler) cookieName(suffix string) string { return h.clientID + "_" + suffix }

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		h.home(w, r)
	case "/login":
		h.login(w, r)
	case "/callback":
		h.callback(w, r)
	case "/logout":
		h.logout(w, r)
	case "/logged-out":
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><meta charset='utf-8'><h1>已退出登录</h1><a href='/login'>重新登录</a>"))
	case "/backchannel-logout":
		h.backchannelLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	c, err := r.Cookie(h.cookieName("session"))
	if err == nil {
		h.mu.Lock()
		s, ok := h.sessions[c.Value]
		if ok && time.Now().After(s.expires) {
			delete(h.sessions, c.Value)
			ok = false
		}
		h.mu.Unlock()
		if ok {
			active, err := h.sessionActive(r.Context(), s.idToken)
			if err != nil {
				http.Error(w, "session check unavailable", http.StatusServiceUnavailable)
				return
			}
			if !active {
				h.mu.Lock()
				delete(h.sessions, c.Value)
				h.mu.Unlock()
				http.SetCookie(w, &http.Cookie{Name: h.cookieName("session"), Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
				http.Redirect(w, r, "/logged-out", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, "<!doctype html><title>%s</title><h1>%s</h1><p>已登录成员 ID：<code>%s</code></p><a href='/logout'>退出所有项目</a>", html.EscapeString(h.clientID), html.EscapeString(h.clientID), html.EscapeString(s.subject))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: h.cookieName("session"), Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/logged-out", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "login unavailable", 500)
		return
	}
	verifier := oauth2.GenerateVerifier()
	nonce, err := randomToken()
	if err != nil {
		http.Error(w, "login unavailable", 500)
		return
	}
	for name, value := range map[string]string{"state": state, "verifier": verifier, "nonce": nonce} {
		http.SetCookie(w, &http.Cookie{Name: h.cookieName(name), Value: value, Path: "/callback", MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	url := h.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *handler) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	values := make(map[string]string)
	for _, name := range []string{"state", "verifier", "nonce"} {
		c, err := r.Cookie(h.cookieName(name))
		if err != nil || c.Value == "" {
			http.Error(w, "invalid login state", 400)
			return
		}
		values[name] = c.Value
	}
	if r.URL.Query().Get("state") != values["state"] || r.URL.Query().Get("code") == "" {
		http.Error(w, "invalid login state", 400)
		return
	}
	for _, name := range []string{"state", "verifier", "nonce"} {
		http.SetCookie(w, &http.Cookie{Name: h.cookieName(name), Path: "/callback", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	client := h.httpClient
	if client == nil { client = http.DefaultClient }
	ctx := oidc.ClientContext(r.Context(), client)
	token, err := h.exchangeCode(r.Context(), r.URL.Query().Get("code"), values["verifier"])
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing ID token", http.StatusBadGateway)
		return
	}
	idToken, err := h.verifier.Verify(ctx, raw)
	if err != nil || idToken.Nonce != values["nonce"] {
		http.Error(w, "invalid ID token", http.StatusForbidden)
		return
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.SID == "" {
		http.Error(w, "missing login session", http.StatusForbidden)
		return
	}
	sid, err := randomToken()
	if err != nil {
		http.Error(w, "session unavailable", 500)
		return
	}
	h.mu.Lock()
	h.sessions[sid] = session{subject: idToken.Subject, sid: claims.SID, idToken: raw, expires: time.Now().Add(time.Hour)}
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: h.cookieName("session"), Value: sid, Path: "/", MaxAge: 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *handler) exchangeCode(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	client := h.httpClient
	if client == nil { client = http.DefaultClient }
	return h.oauth.Exchange(oidc.ClientContext(ctx, client), code, oauth2.VerifierOption(verifier))
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie(h.cookieName("session"))
	if err != nil {
		http.Redirect(w, r, "/logged-out", http.StatusFound)
		return
	}
	h.mu.Lock()
	s, ok := h.sessions[c.Value]
	h.mu.Unlock()
	if !ok || s.idToken == "" {
		http.Redirect(w, r, "/logged-out", http.StatusFound)
		return
	}
	target, err := url.Parse(h.endSessionURL)
	if err != nil {
		http.Error(w, "logout unavailable", http.StatusServiceUnavailable)
		return
	}
	q := target.Query()
	q.Set("id_token_hint", s.idToken)
	q.Set("post_logout_redirect_uri", h.postLogoutURL)
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (h *handler) sessionActive(ctx context.Context, idToken string) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.statusURL, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+idToken)
	client := h.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, errors.New("session status unavailable")
	}
}
