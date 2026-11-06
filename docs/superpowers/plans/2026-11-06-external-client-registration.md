# External OIDC Client Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a new project register its own Hydra OIDC client from a JSON file without changing SSO repository code.

**Architecture:** Preserve the four existing clients in a checked-in default manifest and make the current PowerShell registration script accept an external single-client manifest. Validate a complete manifest before any Hydra write; create missing clients, skip identical clients, and require explicit `-Update` for changed existing clients while preserving fields the tool does not manage.

**Tech Stack:** PowerShell, JSON, Hydra Admin API, existing mocked PowerShell script tests.

**Spec:** `docs/superpowers/specs/2026-11-06-external-client-registration-design.md`

## Global Constraints

- Keep `demo-a`, `demo-b`, `reimbursement-web`, and `multica-web` IDs, redirect URIs, post-logout URIs, scopes, consent settings, and back-channel settings exactly as registered today.
- No-argument `scripts/register-clients.ps1` continues registering the four defaults. `-ConfigPath <path>` processes only that file, resolving relative paths from the caller's current directory.
- Only public authorization-code clients with PKCE and `token_endpoint_auth_method=none` are in scope. Do not add secrets to manifest files.
- Do not modify Go SSO login, tenant admission, identity claims, applications already integrated, or database schema. Do not expose the Hydra Admin API publicly.
- Existing-client changes require `-Update`; unmanaged Hydra fields must survive an update. No registration mode deletes clients.

## Review Focus

- A malformed second client in the default manifest must prevent writes for the first client: parse and validate the whole file before contacting Hydra to mutate it (Task 1 test and Task 2 request assertion).
- A callback containing credentials, fragments, or a non-HTTP scheme must fail before any Admin API write (Task 1 URI cases).
- An existing client using a confidential auth method or different grant type must not be overwritten as a public code client (Task 2 conflict case).
- Updating redirect URIs must preserve unrelated Hydra fields such as `metadata`, `audience`, and `userinfo_signed_response_alg` (Task 2 merged-body assertion).
- External registration must not read, change, or remove any of the four default clients (Task 2 external-only request assertion).

---

### Task 1: Default manifest and strict manifest reader

**Files:**
- Create: `scripts/clients.default.json`
- Modify: `scripts/client-config.ps1`
- Create: `scripts/client-config.test.ps1`

**Interfaces:** `Get-SSOClients -ConfigPath <optional string>` returns normalized client records with `client_id`, `redirect_uris`, `post_logout_redirect_uris`, `backchannel_logout_uri`, `scope` (Hydra string), and `skip_consent`. Omitted path loads `scripts/clients.default.json`; an explicit path accepts exactly one JSON client object. The reader validates all records and returns none on error.

- [ ] Add failing tests for the four exact defaults, one external object resolved from a caller-relative path, missing/unknown fields, duplicate ID in defaults, empty URI arrays, invalid URI forms, and a malformed later default record that yields no partial output.
- [ ] Run `pwsh -NoProfile -File scripts/client-config.test.ps1`; observe a failure caused by the missing manifest reader behavior.
- [ ] Move the four existing values from `Get-SSOClients` to the default JSON file. Implement parsing, strict field/URI/scope validation, and normalization in `client-config.ps1`. Preserve the default clients' current Hydra scope strings and URI order.
- [ ] Re-run `pwsh -NoProfile -File scripts/client-config.test.ps1`; verify all cases pass. Check `git diff --check`.
- [ ] Commit the manifest and parser as `feat: load validated OIDC client manifests`.

### Task 2: Safe registration, documentation, and local acceptance

**Files:**
- Modify: `scripts/register-clients.ps1`
- Modify: `scripts/register-clients.test.ps1`
- Modify: `README.md`

**Interfaces:** `scripts/register-clients.ps1 [-ConfigPath <path>] [-AdminUrl <absolute URI>] [-Update]` consumes Task 1 records. No arguments use the four defaults and `http://localhost:4445`. GET compares the tool-managed fields; POST creates a missing client. A changed existing client without `-Update` fails with a field-level difference. With `-Update`, PUT preserves unmanaged GET fields and updates only tool-managed fields; reject an incompatible auth/grant/response type before writing.

- [ ] Rewrite the mocked API test to fail first for unchanged defaults making zero writes across two runs, external-only POST, external-only repeat with zero writes, changed existing client refused without `-Update`, `-Update` retaining unmanaged fields, incompatible existing client rejected, and invalid manifest producing no Admin writes.
- [ ] Run `pwsh -NoProfile -File scripts/register-clients.test.ps1`; confirm the expected failures against the old hard-coded script.
- [ ] Implement the command parameters and reconciliation. Compare URI arrays as exact sets, normalize scope for comparison, preserve unrelated GET fields when updating, and strip only server-managed read-only fields if the Hydra PUT contract requires it. Fail closed if a fetched record cannot be updated safely. Document default and external commands, private Admin endpoint, and client-side OIDC/logout responsibilities in README.
- [ ] Re-run `pwsh -NoProfile -File scripts/client-config.test.ps1` and `pwsh -NoProfile -File scripts/register-clients.test.ps1`; verify both pass. Run `go test ./...` only if Go code changes (none expected), and `git diff --check`.
- [ ] Read the four current local Hydra clients and compare the managed fields with the default manifest. Run the no-argument command and verify it makes no updates. Create one temporary client from an external manifest, rerun unchanged, update it with `-Update`, then delete only that temporary client via the local Admin API. Confirm the four original client records remain unchanged. If Hydra is unavailable, report this acceptance as unverified rather than claiming it passed.
- [ ] Commit the registrar, tests, and documentation as `feat: register project-owned OIDC clients`.

## Completion

- Review the complete branch diff against the spec, including registration safety and the existing four-client compatibility contract.
- Report targeted test results, local Hydra acceptance, any unverified checks, and a sample command for the next project's repository.
