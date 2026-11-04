# Shared Browser SSO Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow an already signed-in Feishu member to enter either web app without another interactive login.

**Architecture:** Hydra owns the shared browser session. Each app uses one top-level `prompt=none` OIDC code flow, then establishes its own local session. The SSO service handles remembered login requests and restores verified identity claims from PostgreSQL.

**Tech Stack:** Go, PostgreSQL, Hydra/OIDC, Next.js, React, Vitest.

**Spec:** `../specs/2026-11-04-shared-browser-sso-session-design.md`

## Global Constraints

- Preserve existing local account paths, PKCE/state/nonce checks, global logout, deep links and app-specific identity rules.

## Review Focus

- A browser without a Hydra session gets `login_required` and a finite fallback path.
- Forged or mismatched state never triggers an app login.
- A remembered Hydra subject with no verified claims cannot receive an ID token.
- Explicit logout pages do not immediately log in again.
- Scope changes do not leak email to a client lacking the email scope.

### Task 1: SSO remembered login

**Files:** `internal/server/server.go`, `internal/server/server_test.go`, `internal/session/store.go`, `internal/session/store_test.go`, `cmd/sso/main.go`.

- [x] Write tests for remembered and interactive Hydra challenges and persisted verified identity.
- [x] Run the targeted tests and observe the missing behavior.
- [x] Implement Hydra skip handling and identity storage.
- [x] Run SSO tests and commit.

### Task 2: Multica silent OIDC

**Files:** `server/internal/auth/feishu_oidc.go`, `server/internal/handler/feishu_oidc.go`, their tests, `apps/web/app/(auth)/login/page.tsx` and its tests.

- [x] Write tests for `prompt=none`, `login_required`, and one-time login page attempt.
- [x] Observe failures, implement, rerun targeted and relevant broader tests.
- [x] Commit.

### Task 3: Reimbursement silent OIDC

**Files:** `services/reimbursement-api/internal/auth/oidc.go`, `services/reimbursement-api/internal/transport/http/auth_bff.go`, their tests, `apps/web/src/app.tsx` and its tests.

- [x] Write tests for `prompt=none`, fallback on `login_required`, and logged-out suppression.
- [x] Observe failures, implement, rerun targeted and relevant broader tests.
- [x] Commit.
