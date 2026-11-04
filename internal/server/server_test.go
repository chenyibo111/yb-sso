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
)

type fakeFeishu struct{ calls int }

func (f *fakeFeishu) User(_ context.Context, code string) (feishu.Identity, error) {
	f.calls++
	return feishu.Identity{OpenID: "ou_alice", UserID: "u_alice", TenantKey: "tenant-1", Name: "Alice", Email: "Alice@Example.COM"}, nil
}

func TestLoginBindsCallbackToBrowserState(t *testing.T) {
	f := &fakeFeishu{}
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", FeishuAuthorizeURL: "https://open.feishu.cn/open-apis/authen/v1/index", HydraAdminURL: "http://localhost:4445"}, f)
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
	var accepted string
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	s, err := New(Config{AppID: "cli_test", RedirectURI: "http://localhost:9000/auth/feishu/callback", FeishuAuthorizeURL: "https://open.feishu.cn/open-apis/authen/v1/index", HydraAdminURL: hydra.URL}, f)
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
