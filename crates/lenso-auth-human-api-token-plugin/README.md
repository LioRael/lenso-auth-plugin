# Human personal API tokens

Select this removable Native Plugin only for the operators browser profile.
It binds one Account CredentialState provider, one API Token Admin provider and
one Access Control provider. It owns no users, sessions, token records or RBAC.

The source Plugin declares named dependencies `account_state`, `api_tokens`
and `access`. Select the Account live-state instance, the API Token Admin
instance, and the human Account realm's Access Control instance explicitly.
Deployments using the earlier private descriptor must replace its synthetic
`~capability` choices with these names before resolution; provider discovery
does not pick between Account/API state or human/PAT policy instances.
The public Human API Token capability and configuration are unchanged.

Configure the Account instance with an independent issuer/key, an explicit
`management_session_ceiling`, and exact `credential_state_callers`. Account
adds references for its actual stored session to signed Auth assertions.
Current inspection observes disabled identities, parent/session revocation and
expiry. The effective ceiling is the stored issuance ceiling intersected with
the current Account configuration; removing the configuration removes management
admission from existing sessions. Login methods cannot supply either reserved
credential-binding or management-ceiling claim.

`HumanApiTokenConfig::new` selects the exact Account realm issuer/public key,
maximum assertion TTL, maximum token TTL, deployment and lifecycle scope,
and the fixed audiences issued to new PATs. Account assertions need exact
`lenso.auth.human-api-token@1:issue`, `:list`, `:receipt` and `:revoke` audiences. The caller
also needs current `auth.pat.issue`, `auth.pat.list` or `auth.pat.revoke` RBAC
permission in that fixed scope. Issuance intersects requested permissions and
resources with signed and live ceilings and checks each permission/resource
pair against current RBAC. The Console's human route additionally checks current
Management-owned deployment qualification and the Host's admitted EntryPolicy
pairs before forwarding to this bound port.

Live-state, policy and API Token replies retain runtime failures. Unrecognized
domain replies are unavailable outcomes, including during inspection or policy
checks; they do not become permission denials or confirmed failed mutations.

The public source-first `lenso.auth.human-api-token@1` contract accepts no
subject or target URL. List and revoke derive the subject from a currently
verified Account assertion. The internal `lenso.auth.api-token-admin@1` port
accepts a derived subject and is admitted only for the exact configured human
facade instance through `ApiTokenAuthConfig::with_management_callers`; its
default allowlist is empty. Do not bind that internal port to Agent tools, MCP,
or a browser-facing endpoint.

API Token's PostgreSQL migration 2 adds a caller/subject/idempotency-key receipt
in its own schema. Operators must run the owner's explicit upgrade before
starting an existing deployment. Runtime activation never runs migrations.
Issuance records session, peppered verifier and receipt in one transaction.
Only the first committed call returns the raw token. Same-key/same-intent
replay returns current secret-free metadata, including revoked/expired status;
a changed intent conflicts. After an uncertain response, use `receipt` with the
original deployment and idempotency key. It reads the exact caller/derived-subject
committed issuance record and returns current metadata without a secret or write.
A missing record does not prove an in-flight transaction failed and must not
trigger automatic reissuance. Raw token recovery is unavailable. Token list/revoke predicates include
both the derived subject and the exact deployment.

Both lifecycle contracts remain unreleased initial `@1` Descriptor drafts.
The initial role includes issue, list, receipt and revoke; candidate consumers
and providers must use the same exact source revision. This does not claim
compatibility for an already published provider missing receipt.

The real Native PostgreSQL fixture is
`tests/postgres_lifecycle.rs`: it composes Account, API Token, Human facade and
Access Control owner factories and generated clients. It covers live session
references, exact caller denial, current ceilings, realm isolation, machine
rejection, one-time secret/replay, own-subject list/revoke, reserved claims and
session/subject revocation. This fixture does not claim a browser login journey
or a remote Workers deployment proof. Human token lifecycle on API Token's D1
profile returns `UnsupportedProfile`; it performs no fallback write. Account's
D1 current-state path compiles separately but needs its own selected profile
qualification. MFA and idle timeout remain unsupported and cannot be enabled by
an assurance string.
