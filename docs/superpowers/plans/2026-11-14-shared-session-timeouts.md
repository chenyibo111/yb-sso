# Shared Session Timeouts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce one eight-hour SSO session with a 30-minute user inactivity timeout across reimbursement and Multica.

**Architecture:** The SSO store owns per-`sid` deadlines. Relying applications continue checking status and send an authenticated, throttled activity signal on user input. Hydra's remembered-login and ID-token lifetimes align with the absolute limit.

**Tech Stack:** Go, PostgreSQL, React/TypeScript, Hydra v2.3.

**Spec:** `../specs/2026-11-14-shared-session-timeouts.md`

## Global Constraints

- Absolute timeout: 8h; idle timeout: 30m; reimbursement API access token: 15m.
- Explicit logout and timeouts reject the shared `sid` on subsequent server requests.
- Background refresh and polling do not count as activity.

## Review Focus

- Activity after 30m cannot revive an expired session.
- Concurrent status and activity calls cannot extend the 8h limit.
- A remembered Hydra login with an expired `sid` must be rejected.
- A non-SSO Multica session must not be affected.
- SSO store failures fail closed.

### Task 1: SSO deadlines

**Files:** `internal/session/store.go`, `internal/server/server.go`, `internal/server/logout.go`, `internal/server/*_test.go`, `compose.yaml`.

- [x] Add deadline and activity tests. Host Go was unavailable at the initial red stage; the containerized suite ran after implementation.
- [x] Add persisted first-seen/last-activity state, enforce it in login/status, and set Hydra timeouts to 8h.
- [x] Run focused and repository Go tests.

### Task 2: Reimbursement activity

**Files:** `services/reimbursement-api/internal/auth/session.go`, `services/reimbursement-api/internal/transport/http/auth_bff.go`, `apps/web/src/auth/session.tsx` and associated tests in `D:/AI/ai-reimbursement-agent`.

- [x] Write failing tests for authenticated activity reporting and 401 behavior.
- [x] Add BFF activity endpoint and throttled browser input signal; preserve 15m API token.
- [x] Run focused Go/TypeScript tests and type check.

### Task 3: Multica activity

**Files:** `server/internal/auth/sso_status.go`, `server/internal/handler/session.go`, `server/cmd/server/router.go`, `packages/core/platform/core-provider.tsx` and associated tests in `D:/AI/multica`.

- [x] Write failing tests for authenticated SSO activity and client input reporting.
- [x] Add activity endpoint and web input signal; leave non-SSO sessions alone.
- [x] Run focused Go/TypeScript tests and type check.

### Task 4: Final verification

- [x] Review all three diffs, run relevant tests, and document any unverified deployment behavior.

The running local services were not rebuilt; no live browser-to-Hydra login flow was exercised. Existing sessions retain their previously issued token/cookie expiry and may need a fresh login after rollout. Deploy the client applications before the SSO service so their activity reports are available when the central idle deadline starts being enforced.
