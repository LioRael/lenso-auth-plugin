# Optional Console session consumer

`lenso.auth.session-console` uses the existing `lenso.ui.global-contribution@1`
role in `console-global-extensions`. An App selects this Instance separately
from the Account administration workspace. The Console Shell already mounts
global contributions; no Shell protocol or default authentication behavior is
changed. Removing this consumer removes scheduling and the session status link
without deleting accounts, sessions or credentials.

Configure the same explicit `session_cookie_name` and `csrf_cookie_name` as
Web Ingress, the Password browser adapter and the existing renewal adapter.
Both names must be distinct `__Host-` names. This optional browser consumer has
no secret, issuer, management permission or session storage configuration.
Its compiled asset contains only public cookie names. The App Host preflights
the matching cookie/CSRF transport.

The TypeScript source imports the Auth-owned `startSessionRenewal` consumer,
which reuses the existing managed-session browser helper and Web Lock.
Scheduling runs while the surface is active and visible. Console suspension,
AbortSignal disposal and browser page lifecycle stop the timer. Stale/uncertain
responses cause the existing one-time read-only validation, never automatic
business mutation replay. The status links to the Auth-owned login/logout page;
it does not read the HttpOnly credential or choose session policy.

Build the generated asset before compiling the native package:

```sh
bun run build
```

This private source package does not change the root Auth workspace membership
or the dependencies of any existing headless provider. Native and actual browser
qualification are performed by the ordinary product App integration slice.
