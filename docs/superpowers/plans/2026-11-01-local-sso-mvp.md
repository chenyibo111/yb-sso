# Local Feishu SSO MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a local Go OIDC provider that authenticates only members of the configured Feishu test enterprise, plus two local clients that demonstrate single sign-on.

**Architecture:** A Feishu custom app supplies the upstream member identity. A custom Go login service maps its app-scoped open_id to a stable internal subject and accepts Hydra login and consent challenges. Hydra, itself written in Go, handles the downstream OIDC protocol. Two sample clients trust Hydra, not Feishu.

**Tech Stack:** Go 1.27, Ory Hydra 2.3, Feishu OAuth API, PostgreSQL 16, Docker Compose.

**Spec:** `docs/architecture.md`

## Global Constraints

- Feishu is the only login method; no local password or fallback administrator.
- Only the configured test enterprise and users in the app's availability scope may authenticate.
- `.env` is never tracked or logged.
- Use exact localhost callback addresses, authorization code with PKCE, and a stable internal `sub`.

## Review Focus

- OAuth callback with missing or mismatched state must fail without establishing a session.
- A Feishu response with no open_id must fail closed.
- A user outside the configured tenant or app scope must fail closed.
- The same Feishu open_id must resolve to the same internal subject across client apps.
- A redirect URI not registered for a downstream client must be rejected.

---

### Task 1: Feishu identity boundary

**Files:** Create `internal/feishu/client.go`, `internal/feishu/client_test.go`, `internal/identity/subject.go`, `internal/identity/subject_test.go`.

**Interfaces:** `Client.User(ctx, code) (Identity, error)` exchanges a one-time code and retrieves the user; `Subject(appID, openID string) (string, error)` returns a stable subject.

- [ ] Write tests for missing identity, upstream errors, and stable subject mapping.
- [ ] Run `go test ./internal/...` and observe the expected failures.
- [ ] Implement the smallest working adapters and persistence.
- [ ] Run `go test ./internal/...` and observe passes.

### Task 2: OIDC provider and login flow

**Files:** Create `cmd/sso/main.go`, `internal/server/server.go`, `internal/server/server_test.go`, `compose.yaml`, `go.mod`.

**Interfaces:** Hydra exposes OIDC discovery, authorization, token and JWKS; the Go server handles Feishu login/callback and Hydra consent challenges. Client registrations are explicit.

- [ ] Write HTTP tests for state validation, authorization rejection and authentication/session transitions.
- [ ] Run `go test ./...` and observe the expected failures.
- [ ] Implement the OIDC provider around the tested Feishu identity boundary.
- [ ] Run `go test ./...` and observe passes.

### Task 3: Local client demonstrations and runbook

**Files:** Create `cmd/demo/main.go`, `internal/demo/demo_test.go`, `internal/demo/demo.go`, `.env.example`; modify `README.md`.

**Interfaces:** Two local apps run on ports 3000 and 3001 and share the SSO issuer while keeping independent local sessions.

- [ ] Write a client behavior test for callback validation and subject display.
- [ ] Run `go test ./...` and observe the expected failure.
- [ ] Implement both demos and document local startup and Feishu setup.
- [ ] Run `go test ./...`, `go vet ./...`, and a local smoke test.
