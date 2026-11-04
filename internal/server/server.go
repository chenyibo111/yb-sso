package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chenyibo111/yb-sso/internal/feishu"
	"github.com/chenyibo111/yb-sso/internal/identity"
)

type MemberClient interface {
	User(context.Context, string) (feishu.Identity, error)
}

type RevocationStore interface {
	Revoke(context.Context, string) error
	Revoked(context.Context, string) (bool, error)
}

type IdentityStore interface {
	Save(context.Context, string, map[string]string) error
	Load(context.Context, string) (map[string]string, error)
}

type TokenVerifier interface {
	Verify(context.Context, string) (string, error)
}

type Config struct {
	AppID              string
	RedirectURI        string
	FeishuAuthorizeURL string
	HydraAdminURL      string
	Revocations        RevocationStore
	Identities         IdentityStore
	TokenVerifier      TokenVerifier
	ServiceKey         string
}

type pendingLogin struct {
	challenge string
	expires   time.Time
}

type Server struct {
	config  Config
	feishu  MemberClient
	http    *http.Client
	mu      sync.Mutex
	pending map[string]pendingLogin
}

func New(cfg Config, memberClient MemberClient) (*Server, error) {
	if cfg.AppID == "" || cfg.RedirectURI == "" || cfg.HydraAdminURL == "" || memberClient == nil {
		return nil, errors.New("incomplete SSO configuration")
	}
	if cfg.FeishuAuthorizeURL == "" {
		cfg.FeishuAuthorizeURL = "https://open.feishu.cn/open-apis/authen/v1/index"
	}
	if _, err := url.ParseRequestURI(cfg.RedirectURI); err != nil {
		return nil, err
	}
	return &Server{config: cfg, feishu: memberClient, http: &http.Client{Timeout: 10 * time.Second}, pending: make(map[string]pendingLogin)}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login":
		s.login(w, r)
	case "/auth/feishu/callback":
		s.callback(w, r)
	case "/consent":
		s.consent(w, r)
	case "/logout":
		s.logout(w, r)
	case "/session-status":
		s.sessionStatus(w, r)
	case "/internal/session-status":
		s.internalSessionStatus(w, r)
	case "/healthz":
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func randomState() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		http.Error(w, "missing login challenge", http.StatusBadRequest)
		return
	}
	var request struct {
		Skip       bool   `json:"skip"`
		Subject    string `json:"subject"`
		SessionID  string `json:"session_id"`
		RequestURL string `json:"request_url"`
	}
	path := "/admin/oauth2/auth/requests/login?login_challenge=" + url.QueryEscape(challenge)
	if err := s.hydra(r.Context(), http.MethodGet, path, nil, &request); err != nil {
		http.Error(w, "SSO login unavailable", http.StatusBadGateway)
		return
	}
	requested, _ := url.Parse(request.RequestURL)
	silent := requested != nil && requested.Query().Get("prompt") == "none"
	if silent && !request.Skip {
		s.rejectLoginRequired(w, r, challenge)
		return
	}
	if request.Skip {
		if s.config.Revocations != nil {
			if request.SessionID == "" {
				http.Error(w, "SSO login unavailable", http.StatusServiceUnavailable)
				return
			}
			revoked, err := s.config.Revocations.Revoked(r.Context(), request.SessionID)
			if err != nil {
				http.Error(w, "SSO login unavailable", http.StatusServiceUnavailable)
				return
			}
			if revoked {
				if err := s.revokeHydraLoginSession(r.Context(), request.SessionID); err != nil {
					http.Error(w, "SSO login unavailable", http.StatusServiceUnavailable)
					return
				}
				s.rejectLoginRequired(w, r, challenge)
				return
			}
		}
		var claims map[string]string
		if request.Subject != "" && s.config.Identities != nil {
			var err error
			claims, err = s.config.Identities.Load(r.Context(), request.Subject)
			if err != nil {
				http.Error(w, "SSO login unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		verifiedSubject, err := identity.Subject(claims["feishu_app_id"], claims["feishu_open_id"])
		if err != nil || verifiedSubject != request.Subject || claims["feishu_app_id"] != s.config.AppID || claims["feishu_user_id"] == "" || claims["feishu_tenant_key"] == "" {
			if silent {
				s.rejectLoginRequired(w, r, challenge)
				return
			}
		} else {
			var result struct {
				RedirectTo string `json:"redirect_to"`
			}
			path = "/admin/oauth2/auth/requests/login/accept?login_challenge=" + url.QueryEscape(challenge)
			if err := s.hydra(r.Context(), http.MethodPut, path, map[string]any{"subject": request.Subject, "context": claims, "remember": true, "remember_for": 600}, &result); err != nil || result.RedirectTo == "" {
				http.Error(w, "SSO login failed", http.StatusBadGateway)
				return
			}
			http.Redirect(w, r, result.RedirectTo, http.StatusFound)
			return
		}
	}
	state, err := randomState()
	if err != nil {
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	for key, p := range s.pending {
		if time.Now().After(p.expires) {
			delete(s.pending, key)
		}
	}
	s.pending[state] = pendingLogin{challenge: challenge, expires: time.Now().Add(5 * time.Minute)}
	s.mu.Unlock()
	redirect, _ := url.Parse(s.config.RedirectURI)
	http.SetCookie(w, &http.Cookie{Name: "feishu_sso_state", Value: state, Path: redirect.Path, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: redirect.Scheme == "https", MaxAge: 300})
	auth, err := url.Parse(s.config.FeishuAuthorizeURL)
	if err != nil {
		http.Error(w, "invalid Feishu authorization URL", http.StatusInternalServerError)
		return
	}
	q := auth.Query()
	q.Set("app_id", s.config.AppID)
	q.Set("redirect_uri", s.config.RedirectURI)
	q.Set("state", state)
	auth.RawQuery = q.Encode()
	http.Redirect(w, r, auth.String(), http.StatusFound)
}

func (s *Server) revokeHydraLoginSession(ctx context.Context, sid string) error {
	path := "/admin/oauth2/auth/sessions/login?sid=" + url.QueryEscape(sid)
	return s.hydra(ctx, http.MethodDelete, path, nil, nil)
}

func (s *Server) rejectLoginRequired(w http.ResponseWriter, r *http.Request, challenge string) {
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	path := "/admin/oauth2/auth/requests/login/reject?login_challenge=" + url.QueryEscape(challenge)
	if err := s.hydra(r.Context(), http.MethodPut, path, map[string]string{"error": "login_required"}, &result); err != nil || result.RedirectTo == "" {
		http.Error(w, "SSO login failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, result.RedirectTo, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	cookie, err := r.Cookie("feishu_sso_state")
	if err != nil || state == "" || code == "" || cookie.Value != state {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	pending, ok := s.pending[state]
	delete(s.pending, state)
	s.mu.Unlock()
	if !ok || time.Now().After(pending.expires) {
		http.Error(w, "expired login state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "feishu_sso_state", Path: "/auth/feishu/callback", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	member, err := s.feishu.User(r.Context(), code)
	if err != nil {
		http.Error(w, "Feishu login failed", http.StatusBadGateway)
		return
	}
	if member.OpenID == "" || member.UserID == "" || member.TenantKey == "" {
		http.Error(w, "Feishu member identity incomplete", http.StatusForbidden)
		return
	}
	subject, err := identity.Subject(s.config.AppID, member.OpenID)
	if err != nil {
		http.Error(w, "Feishu identity unavailable", http.StatusForbidden)
		return
	}
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	path := "/admin/oauth2/auth/requests/login/accept?login_challenge=" + url.QueryEscape(pending.challenge)
	identityContext := map[string]string{"feishu_open_id": member.OpenID, "feishu_user_id": member.UserID, "feishu_tenant_key": member.TenantKey, "feishu_app_id": s.config.AppID, "name": member.Name}
	if email := strings.ToLower(strings.TrimSpace(member.Email)); email != "" {
		identityContext["email"] = email
	}
	if s.config.Identities != nil {
		if err := s.config.Identities.Save(r.Context(), subject, identityContext); err != nil {
			http.Error(w, "SSO login unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if err := s.hydra(r.Context(), http.MethodPut, path, map[string]any{"subject": subject, "context": identityContext, "remember": true, "remember_for": 600}, &result); err != nil {
		http.Error(w, "SSO login failed", http.StatusBadGateway)
		return
	}
	if result.RedirectTo == "" {
		http.Error(w, "SSO login failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, result.RedirectTo, http.StatusFound)
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		http.Error(w, "missing consent challenge", http.StatusBadRequest)
		return
	}
	base := "/admin/oauth2/auth/requests/consent?consent_challenge=" + url.QueryEscape(challenge)
	var request struct {
		RequestedScope []string          `json:"requested_scope"`
		Context        map[string]string `json:"context"`
	}
	if err := s.hydra(r.Context(), http.MethodGet, base, nil, &request); err != nil {
		http.Error(w, "SSO consent failed", http.StatusBadGateway)
		return
	}
	if len(request.RequestedScope) == 0 {
		http.Error(w, "missing scope", http.StatusBadRequest)
		return
	}
	emailScope := false
	for _, scope := range request.RequestedScope {
		if scope != "openid" && scope != "profile" && scope != "email" && scope != "feishu_identity" {
			http.Error(w, "unsupported scope", http.StatusForbidden)
			return
		}
		if scope == "email" {
			emailScope = true
		}
	}
	for _, name := range []string{"feishu_open_id", "feishu_user_id", "feishu_tenant_key", "feishu_app_id"} {
		if strings.TrimSpace(request.Context[name]) == "" {
			http.Error(w, "missing verified Feishu identity", http.StatusForbidden)
			return
		}
	}
	if request.Context["feishu_app_id"] != s.config.AppID {
		http.Error(w, "wrong Feishu application", http.StatusForbidden)
		return
	}
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	claims := make(map[string]any, len(request.Context)+1)
	for key, value := range request.Context {
		if key != "email" {
			claims[key] = value
		}
	}
	if emailScope {
		if email := strings.TrimSpace(request.Context["email"]); email != "" {
			claims["email"] = email
			claims["email_verified"] = false
		}
	}
	accept := "/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + url.QueryEscape(challenge)
	if err := s.hydra(r.Context(), http.MethodPut, accept, map[string]any{"grant_scope": request.RequestedScope, "session": map[string]any{"id_token": claims}, "remember": true, "remember_for": 600}, &result); err != nil {
		http.Error(w, "SSO consent failed", http.StatusBadGateway)
		return
	}
	if result.RedirectTo == "" {
		http.Error(w, "SSO consent failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, result.RedirectTo, http.StatusFound)
}

func (s *Server) hydra(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.config.HydraAdminURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("Hydra request failed: %w", err)
	}
	defer resp.Body.Close()
	if method == http.MethodDelete && out == nil && resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
