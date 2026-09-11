# Auth Web Session

This removable HTTP adapter exposes the login methods selected by App Plugin
bindings. Use password, federated SSO, or both. It owns no account, password,
OAuth or session database.

- Provides: HTTP Endpoint.
- Requires: one Credential Issuer; zero or one Password; zero or one Federated.
- Lifecycle: reject zero methods or ambiguous method bindings before readiness.
- Configuration: `session_cookie_name`, `csrf_cookie_name`, and `origin` (required
  for password login). Cookie names must use the `__Host-` prefix and match Web
  Ingress. The browser CSRF header is `x-csrf-token`.
- Resources: no private persistent state or listener; Lenso Web owns ingress.
- Authorization: the selected method verifies credentials; the bound issuer
  owns session issuance/revocation; business Plugins authorize the resulting user.
- Removal: deleting a method removes that login choice. Deleting this adapter
  removes browser login/session routes without deleting account-owned records.

`GET /auth/methods` returns configured choices. Password forms POST JSON
`{ "identifier": "...", "password": "..." }` to `/auth/password/login` with
this App's exact Origin. Successful login returns 204 and secure session/CSRF
Cookies. No credential is exposed in JSON. SSO uses `/auth/oidc/start` and
`/auth/oidc/callback`; logout uses `POST /auth/logout`.

The App Host must bind all methods to its common identity/session authority.
The adapter deliberately does not enable public registration or infer providers.
