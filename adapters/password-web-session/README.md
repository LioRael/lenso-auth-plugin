# Password Web Session adapter

This optional native Plugin `lenso.auth.password-web-session` supplies Auth-owned
browser login/exit routes through the existing HTTP Endpoint capability in the
`auth` root slot. It has no lifecycle storage and never migrates or grants access.
It requires the named `passwords` Password capability and `issuer` Credential
Issuer capability. Password owns verification and throttling; Account owns the
opaque sessions. The adapter never calls register or directly issues a credential.

Configuration supplies one canonical HTTPS `allowed_origin` and distinct
`session_cookie_name` / `csrf_cookie_name` values with the `__Host-` prefix. These
names must exactly match the existing Web Ingress and Session Renewal configuration.
No default HTTP exception or client-selected issuer, subject, scope or session
policy exists. Host composition selects the providers and their fixed managed
issuance policy.

POST `/auth/password/login` requires exactly one matching Origin and one
`application/json` content type. Its closed JSON contains only identifier and
password, at most 8 KiB. Any ingress-selected credential causes a 409: users must
log out before changing identity. CSRF entropy is obtained before Password.login
can create a session. A successful result must contain a safe opaque credential
and future RFC3339 expiry. The adapter sets a Secure HttpOnly host session Cookie
and a Secure readable host CSRF Cookie, both at Path=/ with SameSite=Lax. The
no-store JSON response contains only authenticated=true and expires_at. Every
error leaves Cookies unchanged; an unsafe provider result is never installed.

POST `/auth/logout` accepts an empty body, one exact Origin and only a selected
session credential. Web Ingress owns selected-credential provenance and
double-submit CSRF admission; the Endpoint never reads raw Cookie headers or
accepts body credentials. Only a successful Issuer.revoke_credential result clears
both Secure host Cookies and returns 204. Unknown, rejected or unavailable
revocation remains a failure with no Set-Cookie. Other adapters owning the same
logout route must not be selected together.

GET `/auth/methods` reuses Console's existing Auth discovery interface: the
configured Password login action and public CSRF Cookie/header names, without
credential material. It is no-store and rejects request bodies and queries;
Console can configure its existing session CSRF transport without a new protocol.

GET `/auth/login` renders the Auth-owned form with external
`/auth/login/assets.js`, compiled from `browser/main.ts` by the Host build. The
browser first GETs existing `/auth/session/state`; without a valid session it
shows the form. Successful login returns to root Console. Passwords are transient
form/submission values, never stored, logged, placed in a query, or retained for
automatic retry. Auth page logout, login and renewal acquire the existing Console
identity Web Lock `lenso.identity-transition` before the existing renewal Web Lock
`lenso:session-renewal:${csrfCookieName}`. This order coordinates with Console's
identity transitions without duplicating its notification algorithm. Queued
renewal rechecks active state after acquiring the outer lock, so disposal cannot
start a new renewal. The existing Auth renewal helper owns
409/read-validation-once behavior and never replays business requests.

While this page is active and visible it schedules renewal from server metadata,
and observes state when returning from a hidden or back-forward cached page.
Leaving for Console ends page-local scheduling. `startSessionRenewal(config,
onStatus)` exports that active/visible scheduling and returns a cleanup function;
`logoutSession(config)` performs one explicit exit under the shared Web Lock.
An explicitly selected Auth GlobalContribution may mount these functions in its
authenticated Console lifecycle. A login-required status displays a login link;
the scheduler never redirects or replaces Console's identity handling. Importing
the browser module only starts a form if `#auth-login` exists. This adapter does
not add an admin wrapper, hidden iframe or a second session owner. Removing this adapter removes
only the form and login/logout routes; existing account/session storage remains.

Qualification requires real HTTPS cookie handling, existing ingress CSRF policy,
the formal Password/Account providers and explicit operator setup. Local HTTP
requests with manually selected credentials prove Endpoint behavior only. Build,
package, lock updates and native integration checks are owned by the Host writer.
