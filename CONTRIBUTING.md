# Contributing

This repository accepts contributions from any editor and Git client. Keep the
Auth boundary intact: ingress adapters select credentials, Auth authenticates
and issues assertions, and target Plugins authorize from verified assertions.
Do not add wire, database, product, release, or v0.3 platform behavior to the
portable Auth contracts. Credential material, session state, and authorization
policy remain owned by their existing Plugins and Capabilities; never add
secrets to commits, logs, fixtures, or workflow inputs.

## Handoff from a fork

1. Fork this repository and make a focused branch from the current `main`.
2. Run only the validation relevant to the change. Rust changes normally need
   `cargo fmt --all -- --check` and the affected locked Cargo check/test; changes
   to native or database lifecycle code should also exercise the relevant
   PostgreSQL-backed tests. Generated contract changes must use the pinned
   generator and include the locked artifacts. Workflow, script, and docs
   changes should receive focused YAML, shell/Python/Node, link, and diff checks.
3. Open an Issue describing the proposed change, its limitations, the exact
   immutable commit SHA, files changed, commands run, and any unavailable
   services or tests. An Issue is a handoff record, not permission to merge.

A maintainer reviews the fork commit and imports only the reviewed changes into
an isolated checkout. Fork workflows and scripts are untrusted input: inspect
them before execution, preserve action pins and least privilege, and do not
run them with repository secrets. The maintainer reruns focused checks and the
candidate CI workflow from the imported immutable SHA.

## Candidate CI and landing

The final candidate is pushed once to a unique `delta/verify/**` ref. The
candidate CI `Check` job is the authoritative repository proof; it covers the
Auth lifecycle, session, credential, authorization, native, WASM, and database
paths. Candidate CI does not run for ordinary `main` pushes or pull requests.
After the exact candidate SHA and workflow run are verified, a maintainer may
fast-forward `main` to that same SHA only when `main` has not advanced. If it
has advanced, rebase/integrate, review, and run a new candidate instead. A
normal fast-forward is not a force-push and does not publish packages or create
releases.

Delta users may use the reviewed **Delta Land Changes** action or `/land` when
that action is available. `/land` is a Delta operation, not a universal shell
command, Git permission grant, or requirement for contributors. Other agents
and plain Git users should follow the same candidate-ref, immutable-SHA, review,
and normal-fast-forward procedure manually; no Delta account is required.

See [the land skill](.agents/skills/land/SKILL.md) for the concise maintainer
checklist and [the release process](docs/release-process.md) for the separate,
manual release qualification boundary.
