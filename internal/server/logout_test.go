package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeRevocations struct {
	revoked map[string]bool
	err     error
}

func (f *fakeRevocations) Revoke(_ context.Context, sid string) error {
	if f.err != nil {
		return f.err
	}
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[sid] = true
	return nil
}
func (f *fakeRevocations) Revoked(_ context.Context, sid string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[sid], nil
}

type fakeTokenVerifier struct{}

func (fakeTokenVerifier) Verify(_ context.Context, raw string) (string, error) {
	if raw != "valid" {
		return "", errors.New("invalid token")
	}
	return "sid-a", nil
}

func newLogoutServer(t *testing.T, response string, store *fakeRevocations) (*Server, *int, *int) {
	t.Helper()
	accepts := new(int)
	deletes := new(int)
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /admin/oauth2/auth/requests/logout":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(response))
		case "PUT /admin/oauth2/auth/requests/logout/accept":
			*accepts++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/oauth2/sessions/logout?logout_verifier=ok"}`))
		case "DELETE /admin/oauth2/auth/sessions/login":
			if r.URL.Query().Get("sid") != "sid-a" {
				t.Errorf("wrong Hydra session revoked: %q", r.URL.Query().Get("sid"))
			}
			*deletes++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(hydra.Close)
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL, Revocations: store, TokenVerifier: fakeTokenVerifier{}}, &fakeFeishu{})
	if err != nil {
		t.Fatal(err)
	}
	return s, accepts, deletes
}

func TestLogoutRevokesHydraSessionBeforeAccept(t *testing.T) {
	store := &fakeRevocations{}
	s, accepts, deletes := newLogoutServer(t, `{"subject":"fs_alice","sid":"sid-a"}`, store)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=challenge", nil))
	if w.Code != http.StatusFound || !store.revoked["sid-a"] || *deletes != 1 || *accepts != 1 {
		t.Fatalf("logout failed: status=%d revoked=%v deletes=%d accepts=%d", w.Code, store.revoked, *deletes, *accepts)
	}
}

func TestLogoutRejectsMissingSID(t *testing.T) {
	s, accepts, _ := newLogoutServer(t, `{"subject":"fs_alice"}`, &fakeRevocations{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=challenge", nil))
	if w.Code != http.StatusBadGateway || *accepts != 0 {
		t.Fatalf("missing sid accepted: %d", w.Code)
	}
}

func TestLogoutDoesNotAcceptWhenRevocationFails(t *testing.T) {
	s, accepts, _ := newLogoutServer(t, `{"subject":"fs_alice","sid":"sid-a"}`, &fakeRevocations{err: errors.New("database down")})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/logout?logout_challenge=challenge", nil))
	if w.Code != http.StatusServiceUnavailable || *accepts != 0 {
		t.Fatalf("failed revocation accepted: %d", w.Code)
	}
}

func TestSessionStatusRejectsRevokedOrUnverifiableToken(t *testing.T) {
	store := &fakeRevocations{revoked: map[string]bool{"sid-a": true}}
	s, _, _ := newLogoutServer(t, `{"sid":"sid-a"}`, store)
	for _, tc := range []struct {
		token string
		want  int
	}{{"valid", http.StatusUnauthorized}, {"forged", http.StatusUnauthorized}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/session-status", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		s.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("token %s: status %d", tc.token, w.Code)
		}
	}
	delete(store.revoked, "sid-a")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/session-status", nil)
	r.Header.Set("Authorization", "Bearer valid")
	s.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("active session status %d", w.Code)
	}
	store.err = errors.New("database down")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("database outage status %d", w.Code)
	}
}

func TestInternalSessionStatusRequiresKeyAndChecksRevocation(t *testing.T) {
	store := &fakeRevocations{revoked: map[string]bool{"sid-revoked": true}}
	s, _, _ := newLogoutServer(t, `{"sid":"sid-active"}`, store)
	s.config.ServiceKey = "test-service-key-at-least-32-characters"
	call := func(key, body string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/internal/session-status", strings.NewReader(body))
		r.Header.Set("X-SSO-Service-Key", key)
		s.ServeHTTP(w, r)
		return w.Code
	}
	if got := call("wrong", `{"sid":"sid-active"}`); got != http.StatusForbidden {
		t.Fatalf("wrong service key accepted: %d", got)
	}
	if got := call(s.config.ServiceKey, `{"sid":"sid-active"}`); got != http.StatusNoContent {
		t.Fatalf("active session rejected: %d", got)
	}
	if got := call(s.config.ServiceKey, `{"sid":"sid-revoked"}`); got != http.StatusUnauthorized {
		t.Fatalf("revoked session accepted: %d", got)
	}
	if got := call(s.config.ServiceKey, `{"sid":""}`); got != http.StatusBadRequest {
		t.Fatalf("empty session accepted: %d", got)
	}
	store.err = errors.New("database down")
	if got := call(s.config.ServiceKey, `{"sid":"sid-active"}`); got != http.StatusServiceUnavailable {
		t.Fatalf("store outage accepted: %d", got)
	}
}
