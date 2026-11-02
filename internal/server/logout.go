package server

import (
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.config.Revocations == nil {
		http.Error(w, "logout unavailable", http.StatusServiceUnavailable)
		return
	}
	challenge := r.URL.Query().Get("logout_challenge")
	if challenge == "" {
		http.Error(w, "missing logout challenge", http.StatusBadRequest)
		return
	}
	var request struct {
		Subject string `json:"subject"`
		SID     string `json:"sid"`
	}
	path := "/admin/oauth2/auth/requests/logout?logout_challenge=" + url.QueryEscape(challenge)
	if err := s.hydra(r.Context(), http.MethodGet, path, nil, &request); err != nil || request.Subject == "" || request.SID == "" {
		http.Error(w, "invalid logout request", http.StatusBadGateway)
		return
	}
	if err := s.config.Revocations.Revoke(r.Context(), request.SID); err != nil {
		http.Error(w, "logout unavailable", http.StatusServiceUnavailable)
		return
	}
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	path = "/admin/oauth2/auth/requests/logout/accept?logout_challenge=" + url.QueryEscape(challenge)
	if err := s.hydra(r.Context(), http.MethodPut, path, nil, &result); err != nil || result.RedirectTo == "" {
		http.Error(w, "SSO logout failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, result.RedirectTo, http.StatusFound)
}

func (s *Server) sessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.config.Revocations == nil || s.config.TokenVerifier == nil {
		http.Error(w, "session check unavailable", http.StatusServiceUnavailable)
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) > 16*1024 {
		http.Error(w, "invalid session token", http.StatusUnauthorized)
		return
	}
	sid, err := s.config.TokenVerifier.Verify(r.Context(), parts[1])
	if err != nil || sid == "" {
		http.Error(w, "invalid session token", http.StatusUnauthorized)
		return
	}
	revoked, err := s.config.Revocations.Revoked(r.Context(), sid)
	if err != nil {
		http.Error(w, "session check unavailable", http.StatusServiceUnavailable)
		return
	}
	if revoked {
		http.Error(w, "session revoked", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
