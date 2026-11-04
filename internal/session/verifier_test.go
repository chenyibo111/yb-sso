package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestVerifierAcceptsSignedIDTokenAndRejectsMissingSID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL + "/", "authorization_endpoint": server.URL + "/auth", "token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256), Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "key-1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	makeToken := func(sid string) string {
		t.Helper()
		claims := map[string]any{"iss": server.URL + "/", "aud": "demo-a", "sub": "fs_alice", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		if sid != "" {
			claims["sid"] = sid
		}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	verifier, err := NewVerifier(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if sid, err := verifier.Verify(context.Background(), makeToken("sid-a")); err != nil || sid != "sid-a" {
		t.Fatalf("valid token: sid=%q err=%v", sid, err)
	}
	if _, err := verifier.Verify(context.Background(), makeToken("")); err == nil {
		t.Fatal("accepted token without sid")
	}
	if _, err := verifier.Verify(context.Background(), "forged"); err == nil {
		t.Fatal("accepted unsigned token")
	}
}

func TestVerifierUsesInternalJWKSButRequiresPublicIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256), Use: "sig"}}})
	}))
	defer jwks.Close()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "key-1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	makeToken := func(issuer string) string {
		token, err := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "aud": "multica-web", "sub": "fs_alice", "sid": "sid-a", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	verifier := NewVerifierWithJWKS(context.Background(), "http://localhost:4444/", jwks.URL)
	if sid, err := verifier.Verify(context.Background(), makeToken("http://localhost:4444/")); err != nil || sid != "sid-a" {
		t.Fatalf("public issuer token rejected: sid=%q err=%v", sid, err)
	}
	if _, err := verifier.Verify(context.Background(), makeToken("http://hydra:4444/")); err == nil {
		t.Fatal("internal issuer accepted")
	}
}
