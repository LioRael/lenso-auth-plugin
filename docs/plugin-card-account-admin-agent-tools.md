# Auth Account Admin Agent Tools Plugin

## Product job

Let an explicitly configured Console Agent inspect canonical Auth subjects and
sessions, and enable or disable a subject through the Auth owner's existing
administration boundary.

## Contract and capabilities

- Plugin id: `lenso.auth.account-admin.agent-tools`
- Root slot: `tool-providers`
- Provides: `lenso.agent.tool-provider@2`
- Requires exactly one: `lenso.auth.account-admin@1`
- Configuration: none
- Lifecycle: none
- State and resources: none

The catalog provides two parallel-safe reads, `auth_account_admin_list_subjects`
and `auth_account_admin_list_sessions`, plus the exclusive
`auth_account_admin_set_subject_status` mutation. The adapter reuses the
Capability's generated request types and locked request Schemas.

## Authorization and sensitive data

The bound Account Admin provider remains final authorization authority through
its configured `admin_callers`. The adapter does not inspect Account storage or
weaken that caller check. It never exposes `lenso.auth@1`, password, phone,
federated, OIDC, API-token, or Credential Issuer operations. Subject and
session summaries contain no credential material.

Disabling a subject uses the Account owner's existing atomic behavior, which
also revokes that subject's active sessions. Re-enabling a subject does not
restore revoked sessions.

## Ownership and deletion boundary

The Account Auth Plugin remains the sole owner of subjects, sessions, status,
revocation, and authorization policy. This adapter owns only the Agent Tool
catalog and invocation translation. Removing it removes Agent access without
changing Auth facts, authentication behavior, or any credential.

## First observable behavior

When the Plugin is attached to a Console Agent and bound to an authorized
Account Admin provider, the Agent catalog contains exactly three Auth account
administration Tools. An unauthorized caller receives `PermissionDenied` from
the provider-owned check; malformed arguments and missing subjects remain
distinct Tool errors.

## Executable business acceptance

`tests/business_flow.rs` composes the real Account Auth provider and this Tool
adapter through the native Kernel with PostgreSQL. Only the test caller and
logical Secrets values are fixtures. Subjects and sessions are created through
public Directory and Credential Issuer operations, never by writing Account's
private tables.

The acceptance verifies catalog discovery, subject/session queries, status
mutation, immediate credential revocation, persistence across runtime restarts,
provider denial after removing `admin_callers`, no resurrection of revoked
sessions after enablement, cancelled mutations, infrastructure failures, and
removal of the Tool Plugin without deleting Auth facts. Session summaries are
checked against credential and signing material. CI runs this ignored-by-default
database test with its PostgreSQL service.

Run against a disposable PostgreSQL database:

```sh
LENSO_POSTGRES_TEST_URL=postgres://postgres@localhost:5432/postgres \
  cargo test --locked -p lenso-auth-account-admin-agent-tools-plugin \
  --test business_flow -- --include-ignored
```

Authorization here is explicitly delegated to a trusted Plugin Instance, not an
end-user session. Do not reinterpret Console's control token or an Agent approval
mode as an Auth credential. A domain requiring a signed end-user assertion must
add that integration before exposing its operations. This crate is currently a
private linked Plugin; this test is not evidence of npm installation, remote
Connector support, or automatic activation in the default Agent binary.
