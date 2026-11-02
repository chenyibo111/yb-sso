package demo

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestLogoutStartsHydraSessionLogout(t *testing.T) {
	h := &handler{clientID: "demo-a", endSessionURL: "http://localhost:4444/oauth2/sessions/logout", postLogoutURL: "http://localhost:3100/logged-out", sessions: map[string]session{"cookie": {subject: "fs_alice", sid: "sid-a", idToken: "signed-id-token", expires: time.Now().Add(time.Hour)}}}
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: "demo-a_session", Value: "cookie"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("logout status %d", w.Code)
	}
	target, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "localhost:4444" || target.Query().Get("id_token_hint") != "signed-id-token" || target.Query().Get("post_logout_redirect_uri") != "http://localhost:3100/logged-out" {
		t.Fatal("logout did not start Hydra RP-initiated flow")
	}
}

func TestBackchannelLogoutVerifiesTokenAndEvictsOnlyMatchingSession(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	defer jwks.Close()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "key-1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(audience string) string {
		t.Helper()
		claims := map[string]any{"iss": "http://localhost:4444/", "aud": []string{audience}, "iat": time.Now().Unix(), "jti": "unique-1", "sid": "sid-a", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	h := &handler{clientID: "demo-a", issuer: "http://localhost:4444/", jwksURL: jwks.URL, httpClient: jwks.Client(), sessions: map[string]session{"a": {sid: "sid-a"}, "b": {sid: "sid-b"}}}
	send := func(token string) int {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := send(sign("demo-b")); code != http.StatusUnauthorized || len(h.sessions) != 2 {
		t.Fatalf("wrong audience evicted session: %d", code)
	}
	if code := send("forged"); code != http.StatusUnauthorized || len(h.sessions) != 2 {
		t.Fatalf("forged token evicted session: %d", code)
	}
	if code := send(sign("demo-a")); code != http.StatusNoContent || len(h.sessions) != 1 || h.sessions["b"].sid != "sid-b" {
		t.Fatalf("valid logout did not isolate sid: %d", code)
	}
}

func TestProtectedPageRejectsRevokedSessionAndFailsClosedOnOutage(t *testing.T) {
	status := http.StatusUnauthorized
	sso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer signed-id-token" {
			t.Error("missing ID token")
		}
		w.WriteHeader(status)
	}))
	defer sso.Close()
	h := &handler{clientID: "demo-a", statusURL: sso.URL, httpClient: sso.Client(), sessions: map[string]session{"cookie": {subject: "fs_alice", sid: "sid-a", idToken: "signed-id-token", expires: time.Now().Add(time.Hour)}}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "demo-a_session", Value: "cookie"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/logged-out" {
		t.Fatalf("revoked session still usable: %d", w.Code)
	}
	status = http.StatusServiceUnavailable
	h.sessions["cookie"] = session{subject: "fs_alice", sid: "sid-a", idToken: "signed-id-token", expires: time.Now().Add(time.Hour)}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "fs_alice") {
		t.Fatalf("outage exposed protected page: %d", w.Code)
	}
}

func TestBackchannelEvictedBrowserSessionShowsLoggedOutPage(t *testing.T) {
	h := &handler{clientID: "demo-b", sessions: map[string]session{}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "demo-b_session", Value: "evicted"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/logged-out" {
		t.Fatalf("evicted browser session redirected to %q", w.Header().Get("Location"))
	}
}
