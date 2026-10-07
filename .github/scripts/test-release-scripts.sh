#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT/.github/scripts/release-gate.sh"
PLAN="$ROOT/.github/scripts/release-plan.sh"
POSTCONDITION="$ROOT/.github/scripts/release-postcondition.sh"
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

run_postcondition() {
  (
    cd "$test_repo"
    env "$@" bash "$POSTCONDITION"
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
elif [[ "$args" == *"git/ref/tags/"* ]]; then
  if [[ "${MOCK_TAG_KIND:-annotated}" == lightweight ]]; then
    printf '{"object":{"type":"commit","sha":"%s"}}\n' "${MOCK_TAG_TARGET_SHA:-$sha}"
  else
    printf '{"object":{"type":"tag","sha":"%s"}}\n' "$sha"
  fi
elif [[ "$args" == *"git/tags/"* ]]; then
  printf '{"object":{"type":"commit","sha":"%s"}}\n' "${MOCK_TAG_TARGET_SHA:-$sha}"
elif [[ "$args" == *"/releases/tags/"* ]]; then
  tag="${args##*/}"
  printf '{"tag_name":"%s","name":"%s","draft":%s,"prerelease":%s}\n' \
    "${MOCK_RELEASE_TAG:-$tag}" "${MOCK_RELEASE_NAME:-Auth $tag}" \
    "${MOCK_RELEASE_DRAFT:-false}" "${MOCK_RELEASE_PRERELEASE:-false}"
elif [[ "$args" == *"/jobs?"* ]]; then
  printf '[{"jobs":[{"name":"Check","head_sha":"%s","run_attempt":1,"status":"completed","conclusion":"%s"}]}]\n' \
    "$sha" "$job_conclusion"
elif [[ "$args" == *"actions/runs?head_sha="* ]]; then
  printf '[{"workflow_runs":[{"id":999,"workflow_id":294726715,"name":"CI","path":".github/workflows/ci.yml","event":"push","status":"completed","conclusion":"%s","head_branch":"%s","head_sha":"%s","run_attempt":1,"html_url":"https://example.invalid/run/999"}]}]\n' \
    "$run_conclusion" "${MOCK_HEAD_BRANCH:-candidate/test/1}" "$sha"
else
  printf 'unexpected gh api request: %s\n' "$args" >&2
  exit 2
fi
EOF
cat >"$mock_dir/curl" <<'EOF'
#!/usr/bin/env bash
url="${@: -1}"
if [[ "${MOCK_BOOTSTRAP_MISSING:-false}" == true && "$url" == https://crates.io/api/v1/crates/lenso-auth-api-token-plugin/0.1.2 ]]; then
  printf '404\n'
elif [[ " ${MOCK_UNPUBLISHED_PACKAGES:-} " == *" ${url#https://crates.io/api/v1/crates/} "* ]]; then
  printf '404\n'
elif [[ "$url" == "https://crates.io/api/v1/crates/${MOCK_UNPUBLISHED_PACKAGE:-none}/${MOCK_UNPUBLISHED_VERSION:-none}" ]]; then
  printf '404\n'
else
  printf '%s\n' "${MOCK_CURL_STATUS:-200}"
fi
EOF
chmod +x "$mock_dir/gh" "$mock_dir/curl"

expect_failure "invalid full SHA" "full 40-character" \
  run_gate "${base_env[@]}" RELEASE_SHA=not-a-sha
expect_failure "unconfirmed publish" "requires confirmation text publish" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" RELEASE_MODE=publish RELEASE_SET='[{"package_name":"lenso-auth-sdk","version":"0.2.3"}]'
expect_failure "missing candidate CI" "no successful candidate push CI run" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha" MOCK_RUN_CONCLUSION=failure
expect_failure "obsolete candidate namespace" "no successful candidate push CI run" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha" MOCK_HEAD_BRANCH=delta/verify/test/1

run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha"
expect_failure "API token first bootstrap is manual" "requires separately approved manual bootstrap" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" \
    RELEASE_SET='[{"package_name":"lenso-auth-api-token-plugin","version":"0.1.3"}]' \
    PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha" \
    MOCK_UNPUBLISHED_PACKAGE=lenso-auth-api-token-plugin MOCK_UNPUBLISHED_VERSION=0.1.3 MOCK_BOOTSTRAP_MISSING=true

scoped_set='[{"package_name":"lenso-auth-sdk","version":"0.2.4"},{"package_name":"lenso-capability-account-admin","version":"0.1.0"},{"package_name":"lenso-capability-credential-state","version":"0.1.0"}]'
run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" RELEASE_SCOPE=auth-console-upstream \
  RELEASE_SET="$scoped_set" PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha" \
  'MOCK_UNPUBLISHED_PACKAGES=lenso-auth-sdk/0.2.4 lenso-capability-account-admin/0.1.0 lenso-capability-credential-state/0.1.0 lenso-capability-api-token-admin/0.1.0'
expect_failure "scoped release excludes unrelated packages" "exactly its three approved" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" RELEASE_SCOPE=auth-console-upstream \
    RELEASE_SET='[{"package_name":"lenso-capability-api-token-admin","version":"0.1.0"}]' \
    PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha"
expect_failure "scoped release requires complete upstream set" "exactly its three approved" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" RELEASE_SCOPE=auth-console-upstream \
    RELEASE_SET='[{"package_name":"lenso-auth-sdk","version":"0.2.4"}]' \
    PATH="$mock_dir:$PATH" MOCK_SHA="$current_sha"

post_expected='[{"package_name":"lenso-auth-sdk","version":"0.2.3"},{"package_name":"lenso-capability-auth","version":"0.2.0"}]'
post_actual='[{"package_name":"lenso-auth-sdk","version":"0.2.3","tag":"lenso-auth-sdk@0.2.3","prs":[]},{"package_name":"lenso-capability-auth","version":"0.2.0","tag":"lenso-capability-auth@0.2.0","prs":[]}]'
post_env=(
  "${base_env[@]}"
  "RELEASE_SHA=$current_sha"
  "EXPECTED_RELEASE_SET=$post_expected"
  "RELEASE_MODE=publish"
  "RELEASE_CONFIRMATION=publish"
  "RELEASE_ACTION_OUTCOME=success"
  "PATH=$mock_dir:$PATH"
  "MOCK_SHA=$current_sha"
)
run_postcondition "${post_env[@]}" "ACTUAL_RELEASES=$post_actual"
run_postcondition "${post_env[@]}" "ACTUAL_RELEASES=$post_actual" MOCK_TAG_KIND=lightweight
expect_failure "partial live release" "does not match approved release_set" \
  run_postcondition "${post_env[@]}" \
    'ACTUAL_RELEASES=[{"package_name":"lenso-auth-sdk","version":"0.2.3","tag":"lenso-auth-sdk@0.2.3","prs":[]}]'
expect_failure "empty live release" "does not match approved release_set" \
  run_postcondition "${post_env[@]}" 'ACTUAL_RELEASES=[]'
expect_failure "failed release action" "release-plz action did not succeed" \
  run_postcondition "${post_env[@]}" 'RELEASE_ACTION_OUTCOME=failure' 'ACTUAL_RELEASES=[]'
expect_failure "wrong tag target" "does not point to approved source_sha" \
  run_postcondition "${post_env[@]}" "ACTUAL_RELEASES=$post_actual" \
    'MOCK_TAG_TARGET_SHA=0000000000000000000000000000000000000000'
expect_failure "missing registry version" "is not visible on crates.io" \
  run_postcondition "${post_env[@]}" "ACTUAL_RELEASES=$post_actual" \
    MOCK_UNPUBLISHED_PACKAGE=lenso-auth-sdk MOCK_UNPUBLISHED_VERSION=0.2.3
expect_failure "draft GitHub Release" "is not a published, non-prerelease release" \
  run_postcondition "${post_env[@]}" "ACTUAL_RELEASES=$post_actual" MOCK_RELEASE_DRAFT=true
expect_failure "wrong GitHub Release tag" "is not a published, non-prerelease release" \
  run_postcondition "${post_env[@]}" "ACTUAL_RELEASES=$post_actual" MOCK_RELEASE_TAG=wrong-tag
expect_failure "unexpected release tag" "does not match approved tag" \
  run_postcondition "${post_env[@]}" \
    'ACTUAL_RELEASES=[{"package_name":"lenso-auth-sdk","version":"0.2.3","tag":"wrong-tag","prs":[]},{"package_name":"lenso-capability-auth","version":"0.2.0","tag":"lenso-capability-auth@0.2.0","prs":[]}]'
git -C "$test_repo" -c user.name='Release gate fixture' -c user.email='fixture@example.invalid' \
  commit --allow-empty -m 'Advance main after candidate review' >/dev/null
advanced_sha="$(git -C "$test_repo" rev-parse HEAD)"
git -C "$test_repo" push origin HEAD:refs/heads/main >/dev/null
git -C "$test_repo" switch --detach "$current_sha" >/dev/null
expect_failure "advanced main" "source_sha is not the current origin/main" \
  run_gate "${base_env[@]}" RELEASE_SHA="$current_sha" PATH="$mock_dir:$PATH" MOCK_SHA="$advanced_sha"
env EXPECTED_RELEASE_SET='[]' ACTUAL_RELEASES=null bash "$PLAN"
expect_failure "dry-run record mismatch" "unexpected release set" \
  env EXPECTED_RELEASE_SET='[]' ACTUAL_RELEASES='[{"package_name":"lenso-auth-sdk","version":"0.2.3"}]' bash "$PLAN"

printf '%s\n' 'release gate and dry-run plan tests passed'
