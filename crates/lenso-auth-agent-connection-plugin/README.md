# Agent browser connection

Private linked Web Plugin `lenso.auth.agent-connection`. Requires one Auth and
one Delegation provider. The Account provider must allow this exact ingress
instance in `delegation_callers`. Removing the Plugin removes connection routes
and pending handoffs, not Account-owned user sessions or previously issued grants.

Configure a clean App `origin`, human-readable `label`, exact operation `audience`
and `grant_ttl_seconds` (1–3600). The parent login must have at least this much
remaining lifetime; otherwise Account rejects the grant. Hosts select browser
session credentials through their existing ingress policy. Only HTTPS origins
are accepted except clean loopback HTTP for local development.

1. The Agent calls `POST /auth/agent/connection/begin`. Keep `polling_secret`
   server-side, separate from the returned `authorization_url`.
2. Open that URL in the user's browser. The user must already be logged into
   the App. The page displays the configured scope and an explicit consent form.
3. Approval checks the exact Origin and a single-use nonce bound to the selected
   parent credential. It invokes Account Delegation with fixed configuration,
   never a caller-selected user ID or elevated scope.
4. The Agent calls `POST /auth/agent/connection/poll` with JSON `attempt_id` and
   `polling_secret`. A connected result contains the restricted grant. Do not
   forward that response to a model, Session log or diagnostics.

Attempts last five minutes, are bounded to 128 per Instance, and disappear on
restart. Retrying a successful poll returns the same grant during that window;
approval cannot issue another grant. The host should rate-limit public start
and polling endpoints and exclude sensitive request/response bodies from logs.
Responses disable caching, referrer propagation and framing. No grant or polling
secret appears in the authorization URL or consent HTML.

This package is the App-side handoff. It does not implement Agent credential
custody, per-turn identity binding, Tool HTTP ingress, Console UI integration or
a real browser/model acceptance. Its integration test runs generated Endpoint
and Account providers through Kernel with PostgreSQL; selected test sessions are
issued through Credential Issuer, not a live OIDC login.
