package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserExchangesCodeAndGetsIdentity(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open-apis/auth/v3/app_access_token/internal":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["app_id"] != "cli_test" || body["app_secret"] != "secret" {
				t.Error("wrong app credentials")
			}
			_, _ = w.Write([]byte(`{"code":0,"app_access_token":"app-token"}`))
		case "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tenant-token"}`))
		case "/open-apis/authen/v1/access_token":
			if r.Header.Get("Authorization") != "Bearer app-token" {
				t.Error("missing app token")
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "one-time-code" || body["grant_type"] != "authorization_code" {
				t.Error("wrong code exchange")
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"user-token"}}`))
		case "/open-apis/authen/v1/user_info":
			if r.Header.Get("Authorization") != "Bearer user-token" {
				t.Error("missing user token")
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"open_id":"ou_alice","name":"Alice","tenant_key":"tenant-1"}}`))
		case "/open-apis/contact/v3/users/ou_alice":
			if r.URL.Query().Get("user_id_type") != "open_id" || r.Header.Get("Authorization") != "Bearer tenant-token" {
				t.Error("contact lookup must use the SSO application token and open_id type")
			}
			_, _ = w.Write([]byte(`{"code":0,"data":{"user":{"open_id":"ou_alice","user_id":"u_alice","email":"alice@example.com"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := Client{AppID: "cli_test", AppSecret: "secret", TenantKey: "tenant-1", BaseURL: srv.URL, HTTP: srv.Client()}
	got, err := client.User(context.Background(), "one-time-code")
	if err != nil {
		t.Fatal(err)
	}
	if got.OpenID != "ou_alice" || got.Name != "Alice" || got.TenantKey != "tenant-1" || got.UserID != "u_alice" {
		t.Fatalf("unexpected identity: %#v", got)
	}
	if got.Email != "alice@example.com" {
		t.Fatalf("work email = %q", got.Email)
	}
	if len(calls) != 5 {
		t.Fatalf("expected 5 API calls, got %d", len(calls))
	}
}

func TestUserFailsClosedOnMissingOpenID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open-apis/auth/v3/app_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"app_access_token":"app"}`))
		case "/open-apis/authen/v1/access_token":
			_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"user"}}`))
		case "/open-apis/authen/v1/user_info":
			_, _ = w.Write([]byte(`{"code":0,"data":{"name":"Unknown"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := Client{AppID: "cli_test", AppSecret: "secret", TenantKey: "tenant-1", BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := client.User(context.Background(), "code"); err == nil {
		t.Fatal("missing open_id accepted")
	}
}

func TestUserRejectsMissingTenantUserID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open-apis/auth/v3/app_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"app_access_token":"app"}`))
		case "/open-apis/authen/v1/access_token":
			_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"user"}}`))
		case "/open-apis/authen/v1/user_info":
			_, _ = w.Write([]byte(`{"code":0,"data":{"open_id":"ou_alice","tenant_key":"tenant-1"}}`))
		case "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tenant"}`))
		case "/open-apis/contact/v3/users/ou_alice":
			_, _ = w.Write([]byte(`{"code":0,"data":{"user":{"open_id":"ou_alice"}}}`))
		}
	}))
	defer srv.Close()
	client := Client{AppID: "cli_test", AppSecret: "secret", TenantKey: "tenant-1", BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := client.User(context.Background(), "code"); err == nil {
		t.Fatal("member without user_id accepted")
	}
}

func TestUserRejectsMissingOrDifferentTenant(t *testing.T) {
	for _, tenant := range []string{"", "another-tenant"} {
		t.Run(tenant, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/open-apis/auth/v3/app_access_token/internal":
					_, _ = w.Write([]byte(`{"code":0,"app_access_token":"app"}`))
				case "/open-apis/authen/v1/access_token":
					_, _ = w.Write([]byte(`{"code":0,"data":{"access_token":"user"}}`))
				case "/open-apis/authen/v1/user_info":
					_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]string{"open_id": "ou_alice", "tenant_key": tenant}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			client := Client{AppID: "cli_test", AppSecret: "secret", TenantKey: "tenant-1", BaseURL: srv.URL, HTTP: srv.Client()}
			if _, err := client.User(context.Background(), "code"); err == nil {
				t.Fatal("accepted identity outside configured tenant")
			}
		})
	}
}
