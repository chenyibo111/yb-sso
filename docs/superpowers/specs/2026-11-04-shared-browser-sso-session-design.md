# Shared browser SSO session

## Intent

Opening Multica or the reimbursement workbench after signing in to the other should establish the local application session without showing another login screen. Global logout must continue to invalidate both application sessions immediately.

## Approach

Use a top-level OIDC authorization-code redirect with PKCE and `prompt=none` on an unauthenticated app visit. Hydra's browser login session is the shared state; each application keeps its own cookie/session. A missing Hydra session returns `login_required`. Multica then shows its existing login choices; reimbursement starts its existing interactive login. On a first visit to another client, Hydra can return `consent_required` even when the login session is active. Each app then retries one ordinary top-level OIDC authorization; the existing consent handler accepts it without showing a screen or sending the member to Feishu. Explicit logged-out pages suppress the automatic attempt. This avoids depending on third-party iframe cookies or sharing app tokens across origins.

The SSO login service must accept Hydra login challenges with `skip=true` using Hydra's remembered subject. It restores Feishu claims from a server-side record written only after a successful Feishu code exchange. The stored claims are scoped by subject and app ID, never derived from an unverified browser parameter. The existing consent handler issues required claims and remembers each client's grant.

For a Hydra browser session created before this record exists, a silent challenge returns `login_required`. An ordinary authorization revalidates the member with Feishu and then saves the claims. Database outages fail closed.

## Constraints

- Preserve Multica's local and Google login choices, deep links, desktop and CLI handoff.
- Validate OIDC state before treating `login_required` as a silent-login miss.
- Keep the existing central SID revocation and app-side checks.
- Do not automatically reauthenticate from an explicit global logout landing page.
- Preserve current app account identity and provisioning rules.
