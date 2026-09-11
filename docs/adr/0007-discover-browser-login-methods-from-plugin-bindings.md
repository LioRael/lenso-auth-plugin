# ADR 0007: Discover browser login methods from Plugin bindings

Status: accepted.

The App owner selects password, federated login, or both by configuring Plugin
Instances. A Console integration must not make that choice at compile time.

The existing Auth Web Session HTTP adapter consumes zero or one Password and
zero or one Federated provider, with at least one method present. Its lifecycle
rejects ambiguous bindings. `/auth/methods` reports only the selected methods
and the CSRF Cookie/header policy used by browser clients. A failed selected
method never falls through to another provider.

The adapter owns browser request validation, redirects and Cookie responses.
Password and Federated providers keep their private authentication state;
Account remains the common identity and session issuer. Removing a login
provider removes its advertised method without deleting canonical accounts.
No new portable capability or Console-specific behavior is added to Auth.

Password login requires an exact configured App origin and JSON, bounds input,
uses the existing provider's throttling, and returns no credential in response
JSON. The issued session remains HttpOnly; the separate CSRF Cookie is readable
by clients. Web Ingress must select the same Cookie and enforce `x-csrf-token`
on authenticated unsafe requests. Registration is not implicitly enabled.

Implementation target: linked native Rust using the existing HTTP Endpoint
capability. Tests resolve a real Native App with password-only, SSO-only and
combined bindings; exercise login, origin rejection and failure; and preserve
callback rollback and logout revocation coverage.
