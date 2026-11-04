package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/chenyibo111/yb-sso/internal/feishu"
	"github.com/chenyibo111/yb-sso/internal/identity"
)

type fakeFeishu struct{ calls int }

type fakeIdentities struct {
	claims map[string]map[string]string
	loads  int
}

func (f *fakeIdentities) Save(_ context.Context, subject string, claims map[string]string) error {
	if f.claims == nil {
		f.claims = make(map[string]map[string]string)
	}
	f.claims[subject] = claims
	return nil
}

func (f *fakeIdentities) Load(_ context.Context, subject string) (map[string]string, error) {
	f.loads++
	return f.claims[subject], nil
}

func (f *fakeFeishu) User(_ context.Context, code string) (feishu.Identity, error) {
	f.calls++
	return feishu.Identity{OpenID: "ou_alice", UserID: "u_alice", TenantKey: "tenant-1", Name: "Alice", Email: "Alice@Example.COM"}, nil
}

func TestLoginBindsCallbackToBrowserState(t *testing.T) {
	f := &fakeFeishu{}
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"skip": false})
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", FeishuAuthorizeURL: "https://open.feishu.cn/open-apis/authen/v1/index", HydraAdminURL: hydra.URL}, f)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	s.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login?login_challenge=challenge-1", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("login status: %d", login.Code)
	}
	location, err := url.Parse(login.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("app_id") != "cli_test" || location.Query().Get("redirect_uri") != "http://localhost:9000/auth/feishu/callback" {
		t.Fatal("incorrect Feishu authorization URL")
	}
	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("missing state")
	}
	callback := httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?code=code&state="+url.QueryEscape(state), nil)
	bad := httptest.NewRecorder()
	s.ServeHTTP(bad, callback)
	if bad.Code != http.StatusBadRequest || f.calls != 0 {
		t.Fatal("callback without browser cookie accepted")
	}
}

func TestCallbackAcceptsHydraLoginWithStableSubject(t *testing.T) {
	f := &fakeFeishu{}
	identities := &fakeIdentities{}
	var accepted string
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"skip": false})
			return
		}
		if r.URL.Path != "/admin/oauth2/auth/requests/login/accept" || r.URL.Query().Get("login_challenge") != "challenge-1" {
			t.Errorf("unexpected Hydra call: %s", r.URL)
		}
		var body struct {
			Subject string            `json:"subject"`
			Context map[string]string `json:"context"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		accepted = body.Subject
		if body.Context["feishu_user_id"] != "u_alice" || body.Context["feishu_tenant_key"] != "tenant-1" || body.Context["feishu_open_id"] != "ou_alice" || body.Context["feishu_app_id"] != "cli_test" || body.Context["email"] != "alice@example.com" {
			t.Error("Hydra login context is missing verified member identifiers")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/oauth2/auth?login_verifier=ok"}`))
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", FeishuAuthorizeURL: "https://open.feishu.cn/open-apis/authen/v1/index", HydraAdminURL: hydra.URL, Identities: identities}, f)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	s.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login?login_challenge=challenge-1", nil))
	location, _ := url.Parse(login.Header().Get("Location"))
	request := httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	request.AddCookie(login.Result().Cookies()[0])
	callback := httptest.NewRecorder()
	s.ServeHTTP(callback, request)
	if callback.Code != http.StatusFound || !strings.HasPrefix(callback.Header().Get("Location"), "http://localhost:4444/") {
		t.Fatalf("callback failed: %d", callback.Code)
	}
	if accepted == "" || !strings.HasPrefix(accepted, "fs_") || f.calls != 1 {
		t.Fatal("Hydra did not receive Feishu member subject")
	}
	if stored := identities.claims[accepted]; stored["feishu_open_id"] != "ou_alice" || stored["email"] != "alice@example.com" {
		t.Fatal("verified Feishu identity was not saved for a later Hydra login")
	}
}

func TestLoginReusesRememberedHydraSubjectWithVerifiedIdentity(t *testing.T) {
	subject, err := identity.Subject("cli_test", "ou_alice")
	if err != nil {
		t.Fatal(err)
	}
	identities := &fakeIdentities{claims: map[string]map[string]string{subject: {
		"feishu_open_id": "ou_alice", "feishu_user_id": "u_alice", "feishu_tenant_key": "tenant-1", "feishu_app_id": "cli_test", "name": "Alice",
	}}}
	var accepted struct {
		Subject string            `json:"subject"`
		Context map[string]string `json:"context"`
	}
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"skip": true, "subject": subject})
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&accepted)
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/oauth2/auth?login_verifier=ok"}`))
	}))
	defer hydra.Close()
	feishu := &fakeFeishu{}
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL, Identities: identities}, feishu)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login?login_challenge=remembered", nil))
	if w.Code != http.StatusFound || accepted.Subject != subject || accepted.Context["feishu_open_id"] != "ou_alice" || identities.loads != 1 || feishu.calls != 0 {
		t.Fatalf("remembered login failed: status=%d accepted=%+v loads=%d feishu=%d", w.Code, accepted, identities.loads, feishu.calls)
	}
}

func TestLoginDoesNotAcceptRememberedSubjectWithoutVerifiedIdentity(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"skip": true, "subject": "fs_unknown", "request_url": "http://localhost:4444/oauth2/auth?prompt=none"})
			return
		}
		if r.URL.Path != "/admin/oauth2/auth/requests/login/reject" {
			t.Error("unverified subject accepted")
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["error"] != "login_required" {
			t.Errorf("unexpected Hydra rejection: %v", body)
		}
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:8080/auth/feishu/callback?error=login_required&state=test"}`))
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL, Identities: &fakeIdentities{}}, &fakeFeishu{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login?login_challenge=remembered", nil))
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=login_required") {
		t.Fatalf("unverified silent login status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestLoginReverifiesLegacyHydraSessionWithoutIdentityRecord(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("unverified subject accepted")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"skip": true, "subject": "fs_old", "request_url": "http://localhost:4444/oauth2/auth?scope=openid"})
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL, Identities: &fakeIdentities{}}, &fakeFeishu{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login?login_challenge=legacy", nil))
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "https://open.feishu.cn/") {
		t.Fatalf("legacy session was not reverified: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestLoginPromptNoneWithoutRememberedSessionDoesNotOpenFeishu(t *testing.T) {
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"skip": false, "request_url": "http://localhost:4444/oauth2/auth?prompt=none"})
			return
		}
		if r.URL.Path != "/admin/oauth2/auth/requests/login/reject" {
			t.Errorf("unexpected Hydra request: %s", r.URL)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["error"] != "login_required" {
			t.Errorf("unexpected rejection: %v", body)
		}
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:8080/auth/feishu/callback?error=login_required&state=test"}`))
	}))
	defer hydra.Close()
	feishu := &fakeFeishu{}
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL}, feishu)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login?login_challenge=silent", nil))
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=login_required") || feishu.calls != 0 {
		t.Fatalf("prompt=none opened interactive login: status=%d location=%q calls=%d", w.Code, w.Header().Get("Location"), feishu.calls)
	}
}

func TestConsentOmitsEmailWithoutScope(t *testing.T) {
	identity := map[string]string{"feishu_open_id": "ou_alice", "feishu_user_id": "u_alice", "feishu_tenant_key": "tenant-1", "feishu_app_id": "cli_test", "email": "alice@example.com"}
	var claims map[string]any
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"requested_scope": []string{"openid", "profile"}, "context": identity})
			return
		}
		var body struct {
			Session struct {
				IDToken map[string]any `json:"id_token"`
			} `json:"session"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		claims = body.Session.IDToken
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/oauth2/auth?consent_verifier=ok"}`))
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL}, &fakeFeishu{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=c", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("consent status = %d", w.Code)
	}
	if _, ok := claims["email"]; ok {
		t.Fatal("email leaked without scope")
	}
	if _, ok := claims["email_verified"]; ok {
		t.Fatal("email_verified leaked without scope")
	}
}

func TestConsentCarriesVerifiedMemberClaimsIntoIDToken(t *testing.T) {
	identity := map[string]string{"feishu_open_id": "ou_alice", "feishu_user_id": "u_alice", "feishu_tenant_key": "tenant-1", "feishu_app_id": "cli_test", "name": "Alice", "email": "alice@example.com"}
	var claims map[string]any
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"requested_scope": []string{"openid", "profile", "email", "feishu_identity"}, "context": identity})
			return
		}
		var body struct {
			Session struct {
				IDToken map[string]any `json:"id_token"`
			} `json:"session"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		claims = body.Session.IDToken
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/oauth2/auth?consent_verifier=ok"}`))
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL}, &fakeFeishu{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=challenge-1", nil))
	if w.Code != http.StatusFound || claims["feishu_user_id"] != "u_alice" || claims["feishu_open_id"] != "ou_alice" || claims["feishu_tenant_key"] != "tenant-1" || claims["feishu_app_id"] != "cli_test" || claims["email"] != "alice@example.com" || claims["email_verified"] != false {
		t.Fatalf("verified identity claims missing from ID Token: status=%d claims=%v", w.Code, claims)
	}
}
