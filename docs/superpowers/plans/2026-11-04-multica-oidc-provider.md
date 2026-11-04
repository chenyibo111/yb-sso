# Multica OIDC Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish Feishu work email and an OIDC client for Multica, then make the SSO service reachable from both browser and Dockerized Multica.

**Architecture:** Keep Feishu as the sole credential check and Hydra as issuer. Add optional email claims to the existing login/consent flow. Run the Go SSO server in its Compose network so Multica can call it and Hydra through internal service names while validating the public issuer.

**Tech Stack:** Go 1.27, Ory Hydra 2.3, PostgreSQL 16, Docker Compose, PowerShell.

**Spec:** `D:/AI/multica/docs/superpowers/specs/2026-11-04-feishu-sso-only-multica-design.md`

## Global Constraints

- Keep the existing `sub` derivation and `FEISHU_TENANT_KEY` check unchanged.
- Treat Feishu's administrator-entered `email` as unverified; publish `email_verified: false`.
- Never print App Secret, Feishu access tokens, or raw ID Tokens in tests or logs.
- Keep browser issuer `http://localhost:4444/` and internal Hydra access separate.

## Review Focus

- Feishu returns no `email`: login succeeds and the ID Token omits `email`.
- Contact API returns an error: existing identity rejection remains intact.
- Client requests no `email` scope: ID Token contains no email claim.
- `tenant_key` differs: login fails even if an email is present.
- Public issuer and internal JWKS host differ: signature verification still checks the public issuer.

---

## File Map

- `internal/feishu/client.go`: fetch `email` from the already-called contact API.
- `internal/server/server.go`: put optional email into Hydra context and scope-gate ID Token claims.
- `scripts/register-clients.ps1`: register Multica's PKCE OIDC client without changing other clients' semantics.
- `cmd/sso/main.go`, `internal/session/verifier.go`, `Dockerfile.sso`, `compose.yaml`: run SSO inside Docker with separate public issuer and internal API URLs.
- `README.md`, `.env.example`: document only non-secret configuration and commands.

### Task 1: Email claim

**Files:** Modify `internal/feishu/client.go`, `internal/server/server.go`; test `internal/feishu/client_test.go`, `internal/server/server_test.go`.

**Interfaces:** `feishu.Identity.Email string`; consent emits `email` and boolean `email_verified` only when `email` scope was requested and the email is nonempty.

- [ ] Add client tests for present, empty, and omitted contact `email`; add consent tests for scope present/absent and `email_verified == false`.
- [ ] Run `go test ./internal/feishu ./internal/server` and confirm new tests fail for missing behavior.
- [ ] Implement email parsing and a typed consent ID Token map; preserve current verified identity claims and required tenant/app checks.
- [ ] Run `go test ./internal/feishu ./internal/server` and confirm all pass.
- [ ] Commit `feat: publish Feishu email OIDC claim`.

### Task 2: Multica Hydra client

**Files:** Modify `scripts/register-clients.ps1`, `README.md`, `.env.example`; create `scripts/register-clients.test.ps1`.

**Interfaces:** Client ID `multica-web`; scopes `openid profile email feishu_identity`; browser callback `http://localhost:8080/auth/feishu/callback`; authorization code + PKCE; logout redirect `http://localhost:3000/login`.

- [ ] Create `scripts/register-clients.test.ps1` with a mocked Hydra Admin API; assert a second registration run makes no changes and preserves existing demo/reimbursement client settings.
- [ ] Run that check and confirm it fails before the Multica entry is added.
- [ ] Add the Multica client and document local callback, scopes, and logout URL.
- [ ] Run the check, then run `./scripts/register-clients.ps1` against local Hydra and inspect only the client metadata (no secrets).
- [ ] Commit `feat: register Multica OIDC client`.

### Task 3: Containerize SSO service

**Files:** Modify `cmd/sso/main.go`, `internal/session/verifier.go`, `compose.yaml`, `README.md`, `.env.example`; create `Dockerfile.sso`; test `internal/session/verifier_test.go` and runtime configuration tests under `cmd/sso/`.

**Interfaces:** Configurable bind address, Hydra admin URL, expected issuer, and internal JWKS URL; Compose service `sso` listens on port 9000 internally and publishes `127.0.0.1:9000:9000`.

- [ ] Add tests proving the verifier accepts the public issuer using an internal JWKS URL and rejects a wrong issuer; add startup config tests for internal service URLs.
- [ ] Run `go test ./internal/session ./cmd/sso` and confirm new tests fail.
- [ ] Implement the configurable endpoints and container image; keep the host-run dev path available, but use `postgres` and `hydra` service names in Compose.
- [ ] Run `go test ./...`, `docker compose config`, and the local OIDC discovery/status smoke checks.
- [ ] Commit `feat: run SSO service on shared Docker network`.

## Final Verification

- [ ] Use one test member to confirm ID Token contains stable `sub`, expected tenant/app claims, and unverified `email` when scope requested.
- [ ] Confirm `docker compose ps` shows `sso`, `hydra`, and `postgres` healthy and that another container on the shared network can reach `sso:9000` and `hydra:4444`.
- [ ] Record commands and outcomes without secrets.
