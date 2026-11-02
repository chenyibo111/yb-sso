package server

import (
	"context"
	"encoding/json"
	"errors"
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
	return feishu.Identity{OpenID: "ou_alice", Name: "Alice", TenantKey: "tenant-1"}, nil
}

func TestCallbackPersistsIdentityBeforeHydraAccept(t *testing.T) {
	members := &fakeMembers{}
	accepted := false
	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/admin/oauth2/auth/requests/login/accept" {
			var body struct {
				Subject string `json:"subject"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			stored := members.items[body.Subject]
			accepted = stored.OpenID == "ou_alice" && stored.TenantKey == "tenant-1"
			_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/continue"}`))
		}
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", TenantKey: "tenant-1", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL, Members: members}, &fakeFeishu{})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	s.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/login?login_challenge=challenge-1", nil))
	location, _ := url.Parse(login.Header().Get("Location"))
	request := httptest.NewRequest(http.MethodGet, "/auth/feishu/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	request.AddCookie(login.Result().Cookies()[0])
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request)
	if w.Code != http.StatusFound || !accepted {
		t.Fatalf("Hydra accepted before member persisted: status=%d accepted=%v", w.Code, accepted)
	}
}

func TestConsentScopesFeishuOpenIDToRequestedIdentityScope(t *testing.T) {
	for _, tc := range []struct {
		name       string
		scopes     string
		tenant     string
		wantClaim  bool
		wantStatus int
	}{
		{"identity scope", `["openid","profile","feishu_identity"]`, "tenant-1", true, http.StatusFound},
		{"ordinary scope", `["openid","profile"]`, "tenant-1", false, http.StatusFound},
		{"wrong tenant", `["openid","feishu_identity"]`, "tenant-other", false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := &fakeMembers{items: map[string]feishu.Identity{"fs_alice": {OpenID: "ou_alice", Name: "Alice", TenantKey: tc.tenant}}}
			accepted := false
			var claim string
			hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /admin/oauth2/auth/requests/consent":
					_, _ = w.Write([]byte(`{"subject":"fs_alice","requested_scope":` + tc.scopes + `}`))
				case "PUT /admin/oauth2/auth/requests/consent/accept":
					accepted = true
					var body struct {
						Session struct {
							IDToken struct {
								OpenID string `json:"feishu_open_id"`
							} `json:"id_token"`
						} `json:"session"`
					}
					_ = json.NewDecoder(r.Body).Decode(&body)
					claim = body.Session.IDToken.OpenID
					_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/continue"}`))
				}
			}))
			defer hydra.Close()
			s, err := New(Config{AppID: "cli_test", TenantKey: "tenant-1", RedirectURI: "http://localhost:9000/auth/feishu/callback", HydraAdminURL: hydra.URL, Members: members}, &fakeFeishu{})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=challenge-1", nil))
			if w.Code != tc.wantStatus || accepted != (tc.wantStatus == http.StatusFound) || (claim == "ou_alice") != tc.wantClaim {
				t.Fatalf("status=%d accepted=%v claim=%q", w.Code, accepted, claim)
			}
		})
	}
}

type fakeMembers struct {
	items map[string]feishu.Identity
	err   error
}

func (f *fakeMembers) Upsert(_ context.Context, subject string, member feishu.Identity) error {
	if f.err != nil {
		return f.err
	}
	if f.items == nil {
		f.items = map[string]feishu.Identity{}
	}
	f.items[subject] = member
	return nil
}

func (f *fakeMembers) BySubject(_ context.Context, subject string) (feishu.Identity, error) {
	if f.err != nil {
		return feishu.Identity{}, f.err
	}
	member, ok := f.items[subject]
	if !ok {
		return feishu.Identity{}, errors.New("member not found")
	}
	return member, nil
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
			Subject string `json:"subject"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		accepted = body.Subject
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_to":"http://localhost:4444/oauth2/auth?login_verifier=ok"}`))
	}))
	defer hydra.Close()
	s, err := New(Config{AppID: "cli_test", TenantKey: "tenant-1", RedirectURI: "http://localhost:9000/auth/feishu/callback", FeishuAuthorizeURL: "https://open.feishu.cn/open-apis/authen/v1/index", HydraAdminURL: hydra.URL, Members: &fakeMembers{}}, f)
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
