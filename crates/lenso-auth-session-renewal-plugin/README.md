# Managed browser session renewal

This removable HTTP adapter binds exactly one `lenso.auth.managed-session@1`
provider through the named `managed_sessions` requirement. Account owns fixed
normal/operator Instance policy, session storage, rotation, revocation and subject
status. This adapter owns no storage and never chooses policy, TTL, subject,
audience or authority.

Configure distinct `__Host-` session and CSRF Cookie names and one canonical HTTPS
`allowed_origin`, for example `https://app.example`. Names must match the selected
Web Ingress policy. POST `/auth/session/renew`, route ID `auth.session-renewal.renew`,
rotates the credential. GET `/auth/session/state`, route ID
`auth.session-renewal.state`, reads current metadata without rotation. Both require
an empty body and selected session evidence.

## Required ingress contract

Before Endpoint dispatch, Web Ingress must select exactly one `session`
credential, reject ambiguous cookie/bearer evidence, and enforce its double-submit
CSRF policy on this unsafe method. It strips Cookie and CSRF headers before
dispatch. It preserves the Origin header; the adapter independently requires
exactly one Origin equal to `allowed_origin`. Origin verification alone is not
CSRF verification. Do not mount this route on an ingress profile that omits CSRF
admission. A body or raw Cookie header is never an alternate credential source.

The read-only GET accepts one exact allowed Origin, or, when Origin is absent,
exactly one `Sec-Fetch-Site: same-origin` header. Ordinary same-origin browser GET
fetches need no manually supplied Origin. Cross-site, missing and duplicate
provenance headers fail before provider dispatch. The GET sets no Cookie on any
path and returns `authenticated: true` with managed metadata only on a valid
current credential. Ingress still owns credential selection and binding.

The adapter delegates only selected `request.credential` to Account. A success
sets both Cookies with Secure, Path=/, SameSite=Lax and bounded Max-Age; the session
Cookie is HttpOnly. CSRF entropy is obtained before calling Account. The body
contains only session ID and `expires_at`, `absolute_expires_at`, `renew_after`
metadata, never the credential. Success and intentional failures use no-store.
All failures, including provider errors and invalid provider responses, emit no
Set-Cookie and do not clear an existing browser session.

## Browser contract

Use the managed login metadata to schedule an explicit renewal at `renew_after`
while active, before `expires_at`. Serialize renewal across same-origin tabs using
one browser-wide single-flight owner, for example Web Locks. Read the current CSRF
Cookie immediately before sending the admitted request. Do not renew from every
business operation and do not replay business mutations after renewing.

On success, update deadlines from the response. A final renewal may have
`renew_after` at or beyond the effective idle expiry; do not wait past expiry or
schedule another renewal in that case. On `409 stale_credential`, another
request may have committed first: validate the current browser Cookie once using
the application's existing read-only session check, then resume with current
metadata or show login. Do not clear Cookies, repeatedly renew, or loop on 409.
`429 renewal_too_early` waits for the known renewal time; it does not retry
immediately. Invalid, expired or revoked responses require login. Other failures
leave Cookies unchanged and surface the failed request.

Rotation is at-most-once, without plaintext credential escrow. If Account commits
and the browser loses the successful Set-Cookie response, the old credential is
stale and login is required. This limitation must be visible in the consuming
browser flow; the adapter does not claim response-loss recovery.

`browser/session-renewal.mjs` implements the consumer protocol without choosing
application routing or UI. Import `createSessionRenewalClient`,
`createSessionValidator` and `renewalDelay`. Call the state validator once after
login to obtain initial deadlines; the legacy Password login response remains
unchanged. Supply the configured CSRF Cookie/header names; an optional
`validateSession` callback
performs one existing read-only session check and returns
`{ authenticated, metadata? }`. The default validator calls GET
`/auth/session/state` with same-origin credentials and no-store. Also supply
callbacks for new metadata and login UI.
Call `renewOnce(metadata)` only at an active session's scheduled deadline.
`renewalDelay` returns null when no further renewal fits before expiry. Web Locks
are required; an unavailable lock returns `busy` without queueing another refresh.
Same-tab calls share one promise. A 409 stale or uncertain delivery causes exactly
one validation and never automatic renewal/business retry. The helper neither
reads the HttpOnly credential nor writes or clears Cookies.

Run the synthetic browser protocol tests with
`node --test browser/session-renewal.test.mjs` from this package. Real browser
mounting, Ingress CSRF admission and active-session scheduling remain consumer
integration gates.

Removing this adapter removes browser renewal without changing legacy
CredentialIssuer 1.1 issuance/revocation or deleting Account data. Real PG/D1
concurrency and revocation qualification belongs to the Account provider; the
adapter tests use synthetic providers and do not establish those storage proofs.
