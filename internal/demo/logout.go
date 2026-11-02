package demo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

func (h *handler) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid logout token", http.StatusUnauthorized)
		return
	}
	sid, err := h.verifyLogoutToken(r.Context(), r.PostForm.Get("logout_token"))
	if err != nil {
		http.Error(w, "invalid logout token", http.StatusUnauthorized)
		return
	}
	h.mu.Lock()
	for cookie, current := range h.sessions {
		if current.sid == sid {
			delete(h.sessions, cookie)
		}
	}
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) verifyLogoutToken(ctx context.Context, raw string) (string, error) {
	if raw == "" || len(raw) > 16*1024 {
		return "", errors.New("invalid logout token size")
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(parsed.Headers) != 1 || parsed.Headers[0].KeyID == "" {
		return "", errors.New("invalid logout token header")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, h.jwksURL, nil)
	if err != nil {
		return "", err
	}
	client := h.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("JWKS unavailable")
	}
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&keys); err != nil {
		return "", err
	}
	for _, key := range keys.Key(parsed.Headers[0].KeyID) {
		if key.Algorithm != "" && key.Algorithm != string(jose.RS256) {
			continue
		}
		var claims struct {
			Issuer   string                     `json:"iss"`
			Audience []string                   `json:"aud"`
			IssuedAt int64                      `json:"iat"`
			ID       string                     `json:"jti"`
			SID      string                     `json:"sid"`
			Nonce    json.RawMessage            `json:"nonce"`
			Events   map[string]json.RawMessage `json:"events"`
		}
		if err := parsed.Claims(key.Key, &claims); err != nil {
			continue
		}
		if claims.Issuer != h.issuer || len(claims.Audience) != 1 || claims.Audience[0] != h.clientID || claims.ID == "" || claims.SID == "" || len(claims.Nonce) != 0 {
			continue
		}
		rawEvent, ok := claims.Events[logoutEvent]
		if !ok {
			continue
		}
		var event map[string]json.RawMessage
		if err := json.Unmarshal(rawEvent, &event); err != nil || event == nil {
			continue
		}
		issued := time.Unix(claims.IssuedAt, 0)
		if claims.IssuedAt == 0 || time.Since(issued) > 5*time.Minute || time.Until(issued) > time.Minute {
			continue
		}
		return claims.SID, nil
	}
	return "", errors.New("invalid logout token")
}
