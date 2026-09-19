# Land Auth changes

Read [`CONTRIBUTING.md`](../../../CONTRIBUTING.md) first. This skill describes
Delta Land Changes only; `/land` is not a universal shell command or a Git
permission grant. Other agents and plain Git users use the manual path below.

## Manual path

1. Start from the latest `origin/main`; record the base SHA and inspect the
   focused diff. Review untrusted workflows and scripts before running them.
2. Run focused validation for the changed files. Preserve Auth ownership:
   ingress selects credentials, Auth authenticates and issues assertions, and
   target Plugins authorize. Preserve session revocation, credential secrecy,
   authorization boundaries, and Trusted Publishing constraints.
3. Push one final candidate SHA to a unique `delta/verify/<task>/<attempt>` ref.
   Verify the CI workflow was triggered by that exact push/ref/SHA and that the
   required `Check` job passed with its native, WASM, lifecycle, session,
   credential, authorization, and database evidence.
4. Refresh `origin/main`. Only if it is still the recorded base, fast-forward
   `main` to the exact candidate SHA with a normal push. Read back the remote
   SHA and protection settings, then delete the temporary candidate ref.

Do not publish crates, create tags/releases, deploy, rotate credentials, or
change branch protection through this procedure. Release qualification remains
a separately authorized, immutable-SHA, manually dispatched operation.
