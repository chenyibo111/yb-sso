package demo

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func TestLoginCreatesPKCERequestAndBrowserState(t *testing.T) {
	h := &handler{clientID: "demo-a", oauth: oauth2.Config{ClientID: "demo-a", RedirectURL: "http://localhost:3100/callback", Endpoint: oauth2.Endpoint{AuthURL: "http://localhost:4444/oauth2/auth"}, Scopes: []string{"openid", "profile"}}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != "demo-a" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
		t.Fatal("unsafe authorization request")
	}
	if len(w.Result().Cookies()) < 3 {
		t.Fatal("missing transaction cookies")
	}
}

func TestCallbackRejectsMissingBrowserState(t *testing.T) {
	h := &handler{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/callback?state=guess&code=code", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback accepted without state: %d", w.Code)
	}
}
