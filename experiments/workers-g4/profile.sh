#!/usr/bin/env bash
# One clean-checkout command; never loads a Wrangler configuration or remote IDs.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
[[ "$(node --version)" == v26.8.2 ]] || { echo 'D01 requires Node 26.8.2' >&2; exit 1; }
[[ "$(pnpm --version)" == 11.5.0 ]] || { echo 'D01 requires pnpm 11.5.0' >&2; exit 1; }
[[ "$(wasm-bindgen --version)" == 'wasm-bindgen 0.2.127' ]] || { echo 'D01 requires wasm-bindgen-cli 0.2.127' >&2; exit 1; }
profile_tmp="$(mktemp -d "${TMPDIR:-/tmp}/g4-d01-build.XXXXXX")"
trap 'rm -r "$profile_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
pnpm --dir "$root" install --frozen-lockfile --store-dir "$profile_tmp/pnpm-store"
if [[ -x /Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo ]]; then
  export CARGO=/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo
else
  export CARGO="${CARGO:-cargo}"
fi
node "$root/node_modules/@lenso/workers-runtime/build.mjs" \
  --manifest "$root/Cargo.toml" --package lenso-workers-g4-host --out-dir "$profile_tmp/pkg"
node --test "$root/profile.test.mjs" "$root/egress-scope.test.mjs"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test-profile.py"
G4_PROFILE_ARTIFACT_DIR="$profile_tmp/pkg" node "$root/profile.mjs" "${1:-$root/../../docs/workers-g4-d01.raw.json.gz}"
python3 "$root/check-profile.py" "${1:-$root/../../docs/workers-g4-d01.raw.json.gz}"
