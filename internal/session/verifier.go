package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Verifier struct {
	provider *oidc.Provider
	http     *http.Client
}

func NewVerifier(ctx context.Context, issuer string) (*Verifier, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, err
	}
	return &Verifier{provider: provider, http: client}, nil
}

func (v *Verifier) Verify(ctx context.Context, raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[1]) > 12*1024 {
		return "", errors.New("invalid ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var preliminary struct {
		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &preliminary); err != nil {
		return "", errors.New("invalid ID token audience")
	}
	var audience string
	if err := json.Unmarshal(preliminary.Audience, &audience); err != nil {
		var audiences []string
		if err := json.Unmarshal(preliminary.Audience, &audiences); err != nil || len(audiences) != 1 {
			return "", errors.New("invalid ID token audience")
		}
		audience = audiences[0]
	}
	if audience == "" {
		return "", errors.New("invalid ID token audience")
	}
	idToken, err := v.provider.Verifier(&oidc.Config{ClientID: audience}).Verify(oidc.ClientContext(ctx, v.http), raw)
	if err != nil {
		return "", err
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.SID == "" || idToken.Subject == "" {
		return "", errors.New("missing ID token session")
	}
	return claims.SID, nil
}
