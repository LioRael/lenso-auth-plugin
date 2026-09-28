# Release process

Contribution and candidate-landing rules are in [CONTRIBUTING.md](../CONTRIBUTING.md).

The default branch contains six public vNext Rust crates:

- `lenso-capability-auth`
- `lenso-auth-sdk`
- `lenso-capability-credential-issuer`
- `lenso-capability-identity-directory`
- `lenso-capability-password-auth`
- `lenso-auth-api-token-plugin`

All other workspace members are private implementation crates and must keep
`publish = false`.

Release planning is not automatic: this repository does not create Release-plz
PRs and pushes do not trigger release workflows. Publication is manual-only and
starts from an exact immutable SHA already on `main`, with an explicit approved
JSON `release_set`. The dispatch-only workflow has a read-only `dry-run` mode
and a separately gated `publish` mode. Crates.io publication receives no
long-lived Cargo registry token fallback.

## Trusted publishing and first releases

Configure a crates.io Trusted Publisher for every already-published crate with:

- repository: `LioRael/lenso-auth-plugin`
- workflow: `release-plz.yml`
- environment: unset

Trusted Publishing cannot allocate a new crate name. Before invoking the live
workflow, publish the first version of each new crate from a reviewed, clean
`main` checkout with a temporary crates.io token restricted to new-package
publication, then revoke that token immediately. The historical bootstrap set was:

- `lenso-capability-credential-issuer` version `0.1.0`
- `lenso-capability-identity-directory` version `0.1.0`
- `lenso-capability-password-auth` version `0.1.0`

The pending first release is `lenso-auth-api-token-plugin` version `0.1.2`.
First publish and read back the exact Rust framework dependency cohort used by
the Auth candidate, then run Auth candidate CI and package verification against
those registry versions. A checksum-indexed, task-private directory source can
validate candidate `.crate` bytes locally, but it does not satisfy the public
registry gate or authorize the Auth bootstrap. Run
`cargo package --locked -p lenso-auth-api-token-plugin` on the exact reviewed
candidate; that local archive verification does not authorize publication or
prove a registry upload. The release workflow rejects an unbootstrapped API
Token package. First allocate the new crate name from the exact reviewed
`main` commit with the restricted bootstrap credential, then configure its
Trusted Publisher before future
workflow releases. The first upload is a separately approved manual bootstrap,
not a release-plz workflow run. Later unpublished versions enter the exact
`release_set` after candidate CI and landing.

Do not store that bootstrap token in Cargo credentials, repository secrets,
workflow logs, or shell history. After the first release, configure the same
Trusted Publisher for each new crate. Do not run the live workflow until all
six Trusted Publishers match the repository and workflow above.

With the temporary token supplied by a credential helper, the bootstrap
commands are:

```sh
cargo publish --locked -p lenso-capability-credential-issuer
cargo publish --locked -p lenso-capability-identity-directory
cargo publish --locked -p lenso-capability-password-auth
```

For the separately approved API Token bootstrap, run
`cargo publish --locked -p lenso-auth-api-token-plugin` from that exact clean
`main` SHA only after its package and namespace review. Verify the uploaded
registry version and exact archive bytes before preparing a signed linked
Cargo Directory release.

After crates.io confirms each upload, create its matching GitHub release from
the exact reviewed `main` commit. The release tag format is
`<package>@<version>`, matching `release-plz.toml`.

## Release gates

A maintainer must first review the landed candidate, its exact dependency
requirements, and the candidate `Check` run. Then run the workflow dry-run from
`main`, supplying the full landed SHA and exact package set:

```sh
gh workflow run release-plz.yml --ref main \
  -f source_sha=<40-character-main-sha> \
  -f release_set='[{"package_name":"lenso-capability-auth","version":"0.1.0"}]' \
  -f mode=dry-run
```

Inspect the completed run and confirm that it identifies only the intended
unpublished versions against crates.io and the approved source metadata; an
empty release-plz dry-run `releases` output alone does not prove that nothing
will publish. The supplied SHA must still equal the current remote `main` when
the live job rechecks it immediately before publication. If `main` advances,
repeat review and planning for the new SHA. Live publication requires both the
`main` ref and the literal confirmation value `publish`:

```sh
gh workflow run release-plz.yml --ref main \
  -f source_sha=<40-character-main-sha> \
  -f release_set='<exact-package_name/version JSON array>' \
  -f mode=publish -f confirmation=publish
```

The live job reconciles the action's reported package set with the approval,
then reads each exact crates.io version, remote tag commit, and published GitHub
Release. If the action fails or any receipt is missing, inspect the partial
state before considering another run; never blindly retry publication.

The live job obtains a short-lived crates.io credential through GitHub OIDC.
It does not accept a Cargo registry token. Existing versions are immutable and
registry state is authoritative.

The `v0.3` branch retains the old release-line source. Its packages, tags, and
release procedure are not part of `main` and must not be recreated here.

## Qualification boundary

Local checks are focused on the changed files; do not treat a full local suite as
a substitute for candidate CI. The candidate `Check` job is the required
lifecycle, session, credential, authorization, native, WASM, and database proof.
A release-plz dry-run for future versions remains blocked until the API Token
crate has been bootstrapped, all six public crates have Trusted Publishers
configured, and the exact dependency and version set has been reviewed. No
release or package publication is authorized by ordinary contribution or
landing.

Generated bindings must be fresh before packaging. Use the owning
`lenso-contract-codegen` generator rather than editing generated output.
