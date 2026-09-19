# Release process

Contribution and candidate-landing rules are in [CONTRIBUTING.md](../CONTRIBUTING.md).

The default branch contains five public vNext Rust crates:

- `lenso-capability-auth`
- `lenso-auth-sdk`
- `lenso-capability-credential-issuer`
- `lenso-capability-identity-directory`
- `lenso-capability-password-auth`

All other workspace members are private implementation crates and must keep
`publish = false`.

Release planning is not automatic: this repository does not create Release-plz
PRs and pushes do not trigger release workflows. Publication is manual-only and
starts from an exact immutable SHA already on `main`, with an explicit approved
`package@version` set. The workflow has a read-only dry-run mode and a
separately gated live mode. It uses the
explicit versions in the post-extraction workspace as the release baseline, so
release-plz does not derive versions by traversing the imported pre-extraction
history.

The release PR uses `RELEASE_PLZ_TOKEN` when configured, or the repository
GitHub token otherwise. That credential is only for GitHub branch and pull
request operations. Crates.io publication never receives it and has no Cargo
registry token fallback.

## Trusted publishing and first releases

Configure a crates.io Trusted Publisher for every already-published crate with:

- repository: `LioRael/lenso-auth-plugin`
- workflow: `release-plz.yml`
- environment: unset

Trusted Publishing cannot allocate a new crate name. Before invoking the live
workflow, publish the first version of each new crate from a reviewed, clean
`main` checkout with a temporary crates.io token restricted to new-package
publication, then revoke that token immediately:

- `lenso-capability-credential-issuer` version `0.1.0`
- `lenso-capability-identity-directory` version `0.1.0`
- `lenso-capability-password-auth` version `0.1.0`

Do not store that bootstrap token in Cargo credentials, repository secrets,
workflow logs, or shell history. After the first release, configure the same
Trusted Publisher for each new crate. Do not run the live workflow until all
five Trusted Publishers match the repository and workflow above.

With the temporary token supplied by a credential helper, the bootstrap
commands are:

```sh
cargo publish --locked -p lenso-capability-credential-issuer
cargo publish --locked -p lenso-capability-identity-directory
cargo publish --locked -p lenso-capability-password-auth
```

After crates.io confirms each upload, create its matching GitHub release from
the exact reviewed `main` commit. The release tag format is
`<package>@<version>`, matching `release-plz.toml`.

## Release gates

A maintainer must first review the landed candidate, its exact dependency
requirements, and the candidate `Check` run. Then run the workflow dry-run from
`main`, supplying the full landed SHA and exact package set:

```sh
gh workflow run release-plz.yml --ref main \
  -f landed_sha=<40-character-main-sha> \
  -f versions=lenso-capability-auth@0.1.0,lenso-auth-sdk@0.1.0 \
  -f live=false
```

Inspect the completed run and confirm that it identifies only the intended
unpublished versions. Live publication requires both the `main` ref and the
literal confirmation value `publish`:

```sh
gh workflow run release-plz.yml --ref main \
  -f landed_sha=<40-character-main-sha> \
  -f versions=<exact-package@version-set> \
  -f live=true -f confirm=publish
```

The live job obtains a short-lived crates.io credential through GitHub OIDC.
It does not accept a Cargo registry token. Existing versions are immutable and
registry state is authoritative.

The `v0.3` branch retains the old release-line source. Its packages, tags, and
release procedure are not part of `main` and must not be recreated here.

## Qualification boundary

Local checks are focused on the changed files; do not treat a full local suite as
a substitute for candidate CI. The candidate `Check` job is the required
lifecycle, session, credential, authorization, native, WASM, and database proof.
The dry-run is still blocked until all five Trusted Publishers are configured,
the three new crates have been bootstrapped, and the exact dependency and
version set has been reviewed. No release or package publication is authorized
by ordinary contribution or landing.

Generated bindings must be fresh before packaging. Use the owning
`lenso-contract-codegen` generator rather than editing generated output.
