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
	return feishu.Identity{OpenID: "ou_alice", Name: "Alice"}, nil
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
