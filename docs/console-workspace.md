# Optional native Account Console workspace

`console/` owns the optional `lenso.auth.account.console` native UI contribution,
and workspace service. The default
Auth providers remain headless. Removing this UI Instance leaves accounts,
sessions, revocation knowledge and schema state with their existing owners.

The App explicitly selects the UI Instance and mounts local workspace `accounts`.
Its immutable config contains `issuer`, verification-only `public_key`,
`assertion_max_ttl_seconds`, exact canonical `caller_instances`, `deployment`,
`access_scope: {kind, id}`, exact canonical `account_instance` and optional
`allowed_mutations`. The latter defaults to empty and only admits
`set_subject_status` and `revoke_session`. No credentials, signing secret,
database settings, bootstrap or implicit grants belong in this configuration.

Generated Capability ports are Account Admin, Credential State, Credential Issuer
and Access Control. Preparation checks that all three Account roles resolve to the
same configured Account Instance. A same-subject state provider from another
Instance cannot be substituted. Configure that Account's existing
`admin_callers` and `credential_state_callers` to admit this UI Instance; the
App Host owns all binding selections.

Every service call verifies the exact Console caller and current operation
audience `lenso.ui.workspace-service@1:invoke` under one fixed issuer/public
authority and TTL. User assertions with the reserved scoped delegation claim are
rejected. The signed `CredentialBinding` selects current inspection through the
bound same-realm CredentialState. Admission requires active state, exact subject,
user actor kind, assurance, credential/session references, current binding claims,
audience, nondelegation and valid expiry. Current credential expiry must also
cover the signed assertion. Signed and current `ManagementCredentialCeiling`
must both allow the configured deployment, exact permission and fixed scope,
followed by a fresh Access Control check for that subject and permission.
Revocation, subject disablement or ceiling narrowing therefore denies the next
operation. No authorization decision is cached. Already admitted calls retain
the existing verification window; this UI adds no cross-provider transaction.

The owner-local `account-admin` transport admits these strict DTOs:

| Operation | Input | Permission |
| --- | --- | --- |
| `read_policy` | `{}` | `auth.subject.read` |
| `list_subjects` | `{limit, cursor}` | `auth.subject.read` |
| `list_sessions` | `{subject, limit, cursor}` | `auth.session.read` |
| `set_subject_status` | `{subject, status, reason, disabled_until, confirmed:true}` | `auth.subject.status` |
| `revoke_session` | `{session_id, confirmed:true}` | `auth.session.revoke` |

Read limits are 1–200. Sessions require one subject; there is no browser-selected
scope, Account provider or credential reference. Unknown fields reject strict
decoding. Mutation availability is configured explicitly, and each mutation
requires `confirmed=true` plus the same fresh security checks. The browser's
confirmation dialog is intent evidence, not authorization. Session revocation
forwards only the public session ID to CredentialIssuer `revoke`; issuance,
raw `revoke_credential`, registration, PAT creation and private tables are not
exposed. Account remains responsible for subject status and atomic session
revocation on disablement. Account scope authorization is configured for this
exact Account instance; this UI does not invent subject membership semantics.

`read_policy` returns only enabled mutation names, the nonsecret fixed Access
scope and title after ordinary read admission. UI uses these for availability
and display; backend config remains authoritative. SDK scoped reads isolate mounts
and clear displayed data while pending, refreshing or rejected. Mutation success
invalidates account/session/policy reads; ambiguous failure never retries a write
automatically and asks the user to reread current state.

Continuous browser renewal belongs to the separately selected Auth-owned
session Console consumer of the existing global contribution contract. App
integration owns that selection and its configuration. This account management
workspace does not couple renewal to administrator admission or page activity.

Maintained UI source is `console/console/page.tsx` and `workspace.ts`. The Console
SDK compiles assets into `console/dist`; generated `workspace.mjs` is extracted
for native `include_str!`. The selected Host links
`lenso_auth_account_console_plugin::link()`. The optional package has no startup
migration, bootstrap, SQL, automatic permission grant, Agent or storage ownership.
