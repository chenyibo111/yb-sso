# Shared session timeouts

The browser SSO session has an eight-hour absolute limit and a 30-minute inactivity limit. Only explicit user interaction extends the inactivity window. Background token renewal and protected-data polling only check session validity. Every relying application checks the same SSO `sid`; logout or either timeout invalidates all of them on their next server request. The reimbursement API access token stays at 15 minutes. A new project opened while the shared session is active signs in without another Feishu prompt.

Hydra remembers login and consent for eight hours and issues eight-hour ID tokens, matching the current reimbursement BFF's ID-token-bound cookie and logout hint. The SSO service stores first-seen and last-activity times per `sid` and rejects an expired `sid` through both status APIs and remembered login. A silent login returns `login_required`; an interactive login discards the expired Hydra session and continues to Feishu. Activity reports require each application's authenticated backend and the existing service key. Expired sessions cannot be revived by an activity report.

The reimbursement web app and Multica web app send throttled activity reports after genuine pointer or keyboard interaction. Server-side session checks do not extend idle time. Existing sessions created before this change get their first-seen time when first checked after rollout.

## Approaches

- Chosen: central SSO deadline with authenticated activity reports. It preserves one cross-project deadline and keeps background traffic from extending it.
- Rejected: independent project idle timers. A still-valid SSO session would silently sign an idle project in again.
- Rejected: count every status request as activity. Background refresh and polling would keep an abandoned browser signed in.
