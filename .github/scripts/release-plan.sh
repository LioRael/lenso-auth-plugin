#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-set.sh
source "$SCRIPT_DIR/release-set.sh"

fail() {
  echo "::error title=Release plan::$*" >&2
  exit 1
}

: "${EXPECTED_RELEASE_SET:?EXPECTED_RELEASE_SET is required}"

expected="$(release_set_canonical "$EXPECTED_RELEASE_SET")" ||
  fail "expected release set is invalid"
raw_actual="${ACTUAL_RELEASES:-null}"
if [[ "$raw_actual" == "null" || -z "$raw_actual" ]]; then
  actual='[]'
else
  actual="$(release_releases_canonical "$raw_actual")" ||
    fail "release-plz dry-run output is invalid"
fi

if [[ "$actual" != "[]" && "$actual" != "$expected" ]]; then
  fail "release-plz dry-run emitted an unexpected release set: expected ${expected}, got ${actual}"
fi

printf 'Release-plz dry-run completed; action release records: %s\n' "$actual"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### Release-plz dry-run\n\n'
    printf -- '- No publish, tag, or GitHub release operation was authorized by this job.\n'
    printf -- '- The registry-derived release set was validated by the read-only gate.\n'
    printf -- '- Pinned release-plz action records: `%s`\n' "$actual"
  } >>"$GITHUB_STEP_SUMMARY"
fi
