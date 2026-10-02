<a id="vnext-auth-backend-capability-matrix"></a>

# Auth backend capability matrix

This matrix uses the crates on `origin/v0.3` as the restoration baseline. HTTP
route extraction/response mapping, Console manifests/artifacts, and frontend
packages are intentionally excluded. Those are Adapter or UI responsibilities.

| v0.3 owner | Restored behavior | Current owner | Status |
| --- | --- | --- | --- |
| `auth` | canonical users, identities, sessions, disable/enable, session revocation, administrative reads | Account Plugin plus Account Admin Capability | complete |
| `auth-anonymous` | anonymous subject and session creation, stable device-scoped identity | Anonymous Auth Plugin | complete |
| `auth-device` | observe devices and client metadata, trust/primary facts, administrative reads | Device Auth Plugin | complete |
| `auth-password` | register, login, Argon2id hashes, provider-scoped failure limiting | Password Auth Plugin | complete |
| `auth-oauth` | expiring single-use OAuth state, encrypted PKCE verifier, safe return target | OAuth Flow Plugin | complete |
| `auth-github` | authorization start, code exchange, GitHub identity mapping and session | provider-keyed Federated Auth Plugin instance | complete |
| `auth-google` | authorization start, code exchange, verified Google identity mapping and session | provider-keyed Federated Auth Plugin instance | complete |
| `auth-oidc` | metadata/JWKS, authorization-code issuance, PKCE token exchange, ID/access tokens | OIDC Provider Plugin | complete |
| external OIDC login | authorization redirect, PKCE exchange, strict ID-token validation, canonical session issue | OIDC Client Plugin plus bound OAuth Flow, HTTP Client, Directory, and Credential Issuer | complete |
| browser OIDC session | start/callback/logout routes, secure opaque session Cookie, local return redirect, credential-based logout | Auth Web Session Endpoint Plugin plus Web Ingress Cookie/CSRF policy | complete |
| `auth-phone` | normalized phone identities, OTP start/verify/resend limits, phone password set/login | Phone Auth Plugin plus bound SMS Delivery Capability | complete |

The existing API Token Plugin is additional current behavior and remains a peer
credential provider. The Auth Router provides explicit scheme-to-provider
instance selection when a caller accepts more than one `lenso.auth@1`
provider; it never tries another provider after a rejection.

“Complete” here means the relevant contract or Adapter slice, native Plugin,
private-state ownership when applicable, lifecycle/operator seam, and App
Composition behavior exist and pass focused tests and lints. PostgreSQL
acceptance tests are environment-gated by `LENSO_POSTGRES_TEST_URL`. Web UI and
Console artifacts remain intentionally out of scope. The browser OIDC row is
split deliberately: Auth Web Session owns Endpoint responses and Cookie
issuance; Web Ingress owns wire parsing, credential selection, and CSRF
enforcement.
