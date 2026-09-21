#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT/.github/scripts/release-gate.sh"
PLAN="$ROOT/.github/scripts/release-plan.sh"
current_sha="$(git -C "$ROOT" rev-parse HEAD)"
mock_dir="$(mktemp -d)"
test_dir="$(mktemp -d)"
test_remote="$test_dir/origin.git"
test_repo="$test_dir/repo"
trap 'rm -rf "$mock_dir" "$test_dir"' EXIT

git init --bare "$test_remote" >/dev/null
git -C "$ROOT" push "$test_remote" "$current_sha:refs/heads/main" >/dev/null
git -C "$test_remote" symbolic-ref HEAD refs/heads/main
git clone "$test_remote" "$test_repo" >/dev/null

base_env=(
  "GITHUB_REPOSITORY=LioRael/lenso-auth-plugin"
  "GITHUB_REF=refs/heads/main"
  "GITHUB_EVENT_NAME=workflow_dispatch"
  "GITHUB_TOKEN=test-token"
  "RELEASE_SET=[]"
  "RELEASE_MODE=dry-run"
)

run_gate() {
  (
    cd "$test_repo"
    env "$@" bash "$GATE"
  )
}

expect_failure() {
  local label="$1"
  local expected="$2"
  shift 2
  local output
  if output="$("$@" 2>&1)"; then
    printf 'expected failure did not occur: %s\n' "$label" >&2
    exit 1
  fi
  [[ "$output" == *"$expected"* ]] || {
    printf 'failure for %s did not contain %s:\n%s\n' "$label" "$expected" "$output" >&2
    exit 1
  }
}

cat >"$mock_dir/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

args="$*"
sha="${MOCK_SHA:?MOCK_SHA is required}"
run_conclusion="${MOCK_RUN_CONCLUSION:-success}"
job_conclusion="${MOCK_JOB_CONCLUSION:-success}"
if [[ "$args" == *"actions/workflows/ci.yml"* ]]; then
  printf '294726715\n'
elif [[ "$args" == *"git/ref/heads/main"* ]]; then
  printf '%s\n' "$sha"
elif [[ "$args" == *"/jobs?"* ]]; then
  printf '[{"jobs":[{"name":"Check","head_sha":"%s","run_attempt":1,"status":"completed","conclusion":"%s"}]}]\n' \
    "$sha" "$job_conclusion"
elif [[ "$args" == *"actions/runs?head_sha="* ]]; then
  printf '[{"workflow_runs":[{"id":999,"workflow_id":294726715,"name":"CI","path":".github/workflows/ci.yml","event":"push","status":"completed","conclusion":"%s","head_branch":"delta/verify/test/1","head_sha":"%s","run_attempt":1,"html_url":"https://example.invalid/run/999"}]}]\n' \
    "$run_conclusion" "$sha"
else
  printf 'unexpected gh api request: %s\n' "$args" >&2
  exit 2
fi
EOF
cat >"$mock_dir/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${MOCK_CURL_STATUS:-200}"
EOF
chmod +x "$mock_dir/gh" "$mock_dir/curl"

expect_failure "invalid full SHA" "full 40-character" \
  run_gate "${base_env[@]}" RELEASE_SHA=not-a-sha
expect_failure "unconfirmed publish" "requires confirmation text publish" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" RELEASE_MODE=publish RELEASE_SET='[{"package_name":"lenso-auth-sdk","version":"0.2.3"}]'
expect_failure "missing candidate CI" "no successful candidate push CI run" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha" MOCK_RUN_CONCLUSION=failure

run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha"
env EXPECTED_RELEASE_SET='[]' ACTUAL_RELEASES=null bash "$PLAN"
expect_failure "dry-run record mismatch" "unexpected release set" \
  env EXPECTED_RELEASE_SET='[]' ACTUAL_RELEASES='[{"package_name":"lenso-auth-sdk","version":"0.2.3"}]' bash "$PLAN"

printf '%s\n' 'release gate and dry-run plan tests passed'
