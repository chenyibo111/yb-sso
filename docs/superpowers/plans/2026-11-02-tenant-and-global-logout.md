# Tenant Validation and Cross-App Logout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject Feishu identities outside the configured tenant and make an RP-initiated logout invalidate both demo apps and Hydra.

**Architecture:** Feishu user information is checked against one configured tenant key. Hydra handles RP-initiated OIDC logout and sends back-channel logout tokens; the Go SSO service persists revoked Hydra session IDs in PostgreSQL, and demo apps check revocation before serving protected pages so async notification delays cannot leave a usable local session.

**Tech Stack:** Go 1.27, Ory Hydra 2.3, PostgreSQL 16, Docker Compose, go-oidc, go-jose, pgx.

**Spec:** `docs/superpowers/specs/2026-11-02-tenant-and-global-logout-design.md`

## Global Constraints

- Feishu is the sole login method; `FEISHU_TENANT_KEY` is required and missing/mismatched tenant identity fails closed.
- Keep the existing `sub` algorithm and existing client IDs `demo-a`/`demo-b`.
- App Secret and bearer tokens must never appear in commits or logs.
- Hydra 2.3 back-channel logout tokens have `sid`, `aud`, `iat`, `jti`, and `events`, but no required `sub` or `exp`; validate their signature and those claims.
- The demo apps remain available to browsers at `localhost:3100` and `localhost:3101`.

## Review Focus

- A Feishu response with an empty tenant key must be rejected before Hydra accepts login.
- A forged or wrong-client back-channel token must not evict a session.
- A revoked `sid` must not regain access if Hydra's async callback fails.
- A revocation database outage must block protected pages and must not report logout success.
- Logout of one Hydra `sid` must not invalidate another member's `sid`.

---

### Task 1: Tenant validation

**Files:** Modify `internal/feishu/client.go`, `internal/feishu/client_test.go`, `cmd/sso/main.go`, `.env.example`, `README.md`.

**Interfaces:** `feishu.Client.TenantKey string`; `Identity.TenantKey string`; `Client.User` returns error unless the returned key equals the configured key.

- [ ] Write tests for matching, empty, and mismatched tenant keys; run `go test ./internal/feishu` and observe expected failure.
- [ ] Implement tenant comparison and fail-fast startup configuration; rerun tests and `go test ./...`.
- [ ] Document how to set `FEISHU_TENANT_KEY` locally without printing credentials; commit.

### Task 2: Persistent revocation and SSO endpoints

**Files:** Create `internal/session/store.go`, `internal/session/store_test.go`, `internal/server/logout.go`, `internal/server/logout_test.go`; modify `internal/server/server.go`, `cmd/sso/main.go`, `compose.yaml`.

**Interfaces:** `session.Store` exposes `Revoke(ctx, sid string) error` and `Revoked(ctx, sid string) (bool,error)`; SQL implementation stores `sid` as primary key. SSO `GET /logout?logout_challenge=...` reads Hydra request and rejects missing `sid`, writes revocation, accepts logout, redirects to Hydra. `POST /session-status` verifies a bearer ID Token and answers 204 for active or 401 for revoked; database errors return 503.

- [ ] Write store and HTTP tests for revoked/other session, missing challenge or `sid`, persistence failure, invalid ID Token, revoked ID Token; run focused tests and observe expected failure.
- [ ] Implement SQL store and endpoint behavior, with `go-oidc` verification before database lookup; rerun focused tests and full suite.
- [ ] Expose PostgreSQL only on loopback for the native Go service and document `SSO_DATABASE_URL`; commit.

### Task 3: OIDC logout in the demo apps

**Files:** Create `internal/demo/logout.go`, `internal/demo/logout_test.go`; modify `internal/demo/demo.go`, `cmd/demo/main.go`, `scripts/register-clients.ps1`, `compose.yaml`; create `Dockerfile.demo`.

**Interfaces:** Demo sessions retain ID Token and `sid`. `GET /logout` starts Hydra RP-initiated logout; `POST /backchannel-logout` verifies Hydra JWT signature via JWKS and checks issuer, audience, `sid`, recent `iat`, `jti`, event claim, and absent nonce before evicting matching sessions. Protected pages call SSO `/session-status` with the ID Token and fail closed. Two demo containers receive Hydra callbacks through internal Compose DNS.

- [ ] Write tests for logout initiation, valid and forged back-channel tokens, per-`sid` eviction, revoked session, and SSO outage; run focused tests and observe expected failure.
- [ ] Implement logout and session-status calls; rerun focused tests and full suite.
- [ ] Register post-logout and back-channel URIs, add demo containers and local Docker build, then run `docker compose config --quiet`; commit.

### Task 4: Integration and runbook

**Files:** Modify `README.md`, `docs/architecture.md` as needed.

- [ ] Run `go test ./...`, `go vet ./...`, `docker compose config --quiet`, and `git diff --check`.
- [ ] With `FEISHU_TENANT_KEY` filled, run the local login/logout flow for both members and verify A/B/SSO behavior; if a browser step needs the user, leave a precise manual checklist and do not claim it passed.
- [ ] Document setup, restart, logout behavior, and limits; commit and push the feature branch after verification.
