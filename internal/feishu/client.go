package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Identity struct {
	OpenID    string `json:"open_id"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	TenantKey string `json:"tenant_key"`
}

type Client struct {
	AppID     string
	AppSecret string
	TenantKey string
	BaseURL   string
	HTTP      *http.Client
}

func (c Client) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return "https://open.feishu.cn"
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c Client) request(ctx context.Context, method, path, bearer string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("Feishu request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Feishu returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// User exchanges a Feishu authorization code and reads the authenticated member.
func (c Client) User(ctx context.Context, code string) (Identity, error) {
	if c.AppID == "" || c.AppSecret == "" || c.TenantKey == "" || strings.TrimSpace(code) == "" {
		return Identity{}, errors.New("missing Feishu credentials or authorization code")
	}
	var app struct {
		Code  int    `json:"code"`
		Token string `json:"app_access_token"`
	}
	if err := c.request(ctx, http.MethodPost, "/open-apis/auth/v3/app_access_token/internal", "", map[string]string{"app_id": c.AppID, "app_secret": c.AppSecret}, &app); err != nil {
		return Identity{}, err
	}
	if app.Code != 0 || app.Token == "" {
		return Identity{}, errors.New("Feishu app authentication failed")
	}
	var token struct {
		Code int `json:"code"`
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := c.request(ctx, http.MethodPost, "/open-apis/authen/v1/access_token", app.Token, map[string]string{"grant_type": "authorization_code", "code": code, "app_id": c.AppID, "app_secret": c.AppSecret}, &token); err != nil {
		return Identity{}, err
	}
	if token.Code != 0 || token.Data.AccessToken == "" {
		return Identity{}, errors.New("Feishu code exchange failed")
	}
	var user struct {
		Code int      `json:"code"`
		Data Identity `json:"data"`
	}
	if err := c.request(ctx, http.MethodGet, "/open-apis/authen/v1/user_info", token.Data.AccessToken, nil, &user); err != nil {
		return Identity{}, err
	}
	if user.Code != 0 || user.Data.OpenID == "" || user.Data.TenantKey != c.TenantKey {
		return Identity{}, errors.New("Feishu member identity unavailable")
	}
	var tenantToken struct {
		Code  int    `json:"code"`
		Token string `json:"tenant_access_token"`
	}
	if err := c.request(ctx, http.MethodPost, "/open-apis/auth/v3/tenant_access_token/internal", "", map[string]string{"app_id": c.AppID, "app_secret": c.AppSecret}, &tenantToken); err != nil {
		return Identity{}, err
	}
	if tenantToken.Code != 0 || tenantToken.Token == "" {
		return Identity{}, errors.New("Feishu tenant authentication failed")
	}
	var contact struct {
		Code int `json:"code"`
		Data struct {
			User struct {
				OpenID string `json:"open_id"`
				UserID string `json:"user_id"`
			} `json:"user"`
		} `json:"data"`
	}
	path := "/open-apis/contact/v3/users/" + url.PathEscape(user.Data.OpenID) + "?user_id_type=open_id"
	if err := c.request(ctx, http.MethodGet, path, tenantToken.Token, nil, &contact); err != nil {
		return Identity{}, err
	}
	if contact.Code != 0 || contact.Data.User.OpenID != user.Data.OpenID || strings.TrimSpace(contact.Data.User.UserID) == "" {
		return Identity{}, errors.New("Feishu user ID unavailable")
	}
	user.Data.UserID = contact.Data.User.UserID
	return user.Data, nil
}
