package main

import "testing"

func TestRuntimeConfigUsesInternalHydraEndpoints(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "http://localhost:4444/")
	t.Setenv("HYDRA_ADMIN_URL", "http://hydra:4445")
	t.Setenv("HYDRA_JWKS_URL", "http://hydra:4444/.well-known/jwks.json")
	t.Setenv("SSO_BIND_ADDRESS", "0.0.0.0:9000")
	config := runtimeConfigFromEnv()
	if config.Issuer != "http://localhost:4444/" || config.AdminURL != "http://hydra:4445" || config.JWKSURL != "http://hydra:4444/.well-known/jwks.json" || config.BindAddress != "0.0.0.0:9000" {
		t.Fatalf("unexpected runtime config: %#v", config)
	}
}
