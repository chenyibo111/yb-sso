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
	issuer   string
	keySet   oidc.KeySet
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

// NewVerifierWithJWKS validates the public issuer while fetching keys from a
// container-reachable endpoint. The internal address never becomes an issuer.
func NewVerifierWithJWKS(ctx context.Context, issuer, jwksURL string) *Verifier {
	client := &http.Client{Timeout: 10 * time.Second}
	keySet := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), jwksURL)
	return &Verifier{issuer: issuer, keySet: keySet, http: client}
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
	var verifier *oidc.IDTokenVerifier
	if v.keySet != nil {
		verifier = oidc.NewVerifier(v.issuer, v.keySet, &oidc.Config{ClientID: audience})
	} else {
		verifier = v.provider.Verifier(&oidc.Config{ClientID: audience})
	}
	idToken, err := verifier.Verify(oidc.ClientContext(ctx, v.http), raw)
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
