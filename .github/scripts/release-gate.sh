#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-set.sh
source "$SCRIPT_DIR/release-set.sh"

fail() {
  echo "::error title=Release gate::$*" >&2
  exit 1
}

require_env() {
  [[ -n "${!1:-}" ]] || fail "missing required environment variable: $1"
}

for variable in GITHUB_TOKEN GITHUB_REPOSITORY GITHUB_REF GITHUB_EVENT_NAME RELEASE_SHA RELEASE_SET RELEASE_MODE; do
  require_env "$variable"
done

[[ "$GITHUB_REPOSITORY" == "LioRael/lenso-auth-plugin" ]] ||
  fail "release workflow is restricted to LioRael/lenso-auth-plugin"
[[ "$GITHUB_REF" == "refs/heads/main" ]] ||
  fail "release workflow must run from refs/heads/main"
[[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]] ||
  fail "release workflow requires workflow_dispatch"
case "$RELEASE_MODE" in
  dry-run|publish) ;;
  *) fail "unsupported release mode: $RELEASE_MODE" ;;
esac
if [[ "$RELEASE_MODE" == "publish" ]]; then
  [[ "${RELEASE_CONFIRMATION:-}" == "publish" ]] ||
    fail "publish mode requires confirmation text publish"
fi

source_sha="${RELEASE_SHA,,}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] ||
  fail "source_sha must be a full 40-character hexadecimal commit SHA"
release_set="$(release_set_canonical "$RELEASE_SET")" ||
  fail "release_set is not a valid package_name/version JSON array"
if [[ "$RELEASE_MODE" == "publish" && "$release_set" == "[]" ]]; then
  fail "publish mode requires a non-empty release_set"
fi

git fetch origin main --no-tags >/dev/null
main_sha="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq '.object.sha')" ||
  fail "could not read the remote main SHA"
[[ "$main_sha" =~ ^[0-9a-f]{40}$ ]] ||
  fail "remote main did not return a full commit SHA"
local_main_sha="$(git rev-parse refs/remotes/origin/main 2>/dev/null)" ||
  fail "origin/main is unavailable after fetch"
[[ "$local_main_sha" == "$main_sha" ]] ||
  fail "local origin/main does not match the remote main readback"

[[ "$(git rev-parse HEAD)" == "$source_sha" ]] ||
  fail "checked-out source does not match source_sha"
git cat-file -e "$source_sha^{commit}" ||
  fail "source_sha is not a commit available to the checkout"
git cat-file -e "$main_sha^{commit}" ||
  fail "remote main SHA is not a commit available to the checkout"
git merge-base --is-ancestor "$source_sha" "$main_sha" ||
  fail "source_sha is not reachable from the current origin/main"

metadata="$(cargo metadata --locked --no-deps --format-version 1)" ||
  fail "cargo metadata failed for source_sha"
registry_release_set='[]'
while IFS=$'\t' read -r package expected_version; do
  package_record="$(
    jq -c --arg package "$package" \
      '[.packages[] | select(.name == $package)] | if length == 1 then .[0] else empty end' \
      <<<"$metadata"
  )"
  [[ -n "$package_record" ]] ||
    fail "release_set names a package outside this workspace: $package"
  manifest="$(jq -r '.manifest_path' <<<"$package_record")"
  grep -Eq '^[[:space:]]*publish[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$manifest" ||
    fail "package is not in the publish=true allowlist: $package"
  actual_version="$(jq -r '.version' <<<"$package_record")"
  [[ "$actual_version" == "$expected_version" ]] ||
    fail "release_set version for $package is $expected_version, source has $actual_version"
done < <(jq -r '.[] | [.package_name, .version] | @tsv' <<<"$release_set")

while IFS=$'\t' read -r package version manifest; do
  grep -Eq '^[[:space:]]*publish[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$manifest" ||
    continue
  registry_status="$(
    curl --silent --show-error --location --retry 2 \
      --user-agent 'Lenso-release-gate/1.0 (https://github.com/LioRael/lenso-auth-plugin)' \
      --output /dev/null --write-out '%{http_code}' \
      "https://crates.io/api/v1/crates/${package}/${version}"
  )" || fail "could not query crates.io for ${package} ${version}"
  case "$registry_status" in
    200) ;;
    404)
      registry_release_set="$(
        jq -c --arg package "$package" --arg version "$version" \
          '. + [{package_name: $package, version: $version}]' <<<"$registry_release_set"
      )"
      ;;
    *) fail "unexpected crates.io response ${registry_status} for ${package} ${version}" ;;
  esac
done < <(jq -r '.packages[] | [.name, .version, .manifest_path] | @tsv' <<<"$metadata")
registry_release_set="$(jq -c 'sort_by(.package_name)' <<<"$registry_release_set")"
[[ "$registry_release_set" == "$release_set" ]] ||
  fail "release_set does not match the read-only crates.io plan: expected ${release_set}, registry plan ${registry_release_set}"

workflow_id="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml" --jq '.id')" ||
  fail "could not read the CI workflow identity"
[[ "$workflow_id" =~ ^[0-9]+$ ]] ||
  fail "CI workflow identity is not numeric"
runs_payload="$(
  gh api --paginate --slurp \
    "repos/${GITHUB_REPOSITORY}/actions/runs?head_sha=${source_sha}&event=push&per_page=100"
)" || fail "could not read CI runs for source_sha"
ci_run="$(
  jq -c --arg sha "$source_sha" --argjson workflow_id "$workflow_id" '
    [
      .[]?.workflow_runs[]?
      | select(
          .workflow_id == $workflow_id
          and .path == ".github/workflows/ci.yml"
          and .name == "CI"
          and .event == "push"
          and ((.head_branch // "") | startswith("delta/verify/"))
          and .head_sha == $sha
          and .status == "completed"
          and .conclusion == "success"
        )
    ]
    | sort_by([.run_number, .run_attempt])
    | last // empty
  ' <<<"$runs_payload"
)" || fail "could not inspect CI run identity"
[[ -n "$ci_run" ]] ||
  fail "no successful candidate push CI run exists for this exact source_sha"

ci_run_id="$(jq -r '.id' <<<"$ci_run")"
ci_run_url="$(jq -r '.html_url' <<<"$ci_run")"
ci_run_attempt="$(jq -r '.run_attempt' <<<"$ci_run")"
jobs_payload="$(
  gh api --paginate --slurp \
    "repos/${GITHUB_REPOSITORY}/actions/runs/${ci_run_id}/attempts/${ci_run_attempt}/jobs?per_page=100"
)" || fail "could not read jobs for CI run ${ci_run_id}"
check_count="$(
  jq --arg sha "$source_sha" --argjson attempt "$ci_run_attempt" '
    [
      .[]?.jobs[]?
      | select(.name == "Check" and .head_sha == $sha and .run_attempt == $attempt)
    ]
    | length
  ' <<<"$jobs_payload"
)"
check_success="$(
  jq --arg sha "$source_sha" --argjson attempt "$ci_run_attempt" '
    [
      .[]?.jobs[]?
      | select(
          .name == "Check"
          and .head_sha == $sha
          and .run_attempt == $attempt
          and .status == "completed"
          and .conclusion == "success"
        )
    ]
    | length
  ' <<<"$jobs_payload"
)"
[[ "$check_count" == "1" && "$check_success" == "1" ]] ||
  fail "exact CI run ${ci_run_id} attempt ${ci_run_attempt} does not contain one successful Check job for source_sha"

printf 'Release gate passed for %s\n' "$source_sha"
printf 'origin/main: %s\n' "$main_sha"
printf 'CI run: %s (attempt %s)\n' "$ci_run_url" "$ci_run_attempt"
printf 'release_set: %s\n' "$release_set"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'source_sha=%s\n' "$source_sha"
    printf 'main_sha=%s\n' "$main_sha"
    printf 'ci_run_id=%s\n' "$ci_run_id"
    printf 'ci_run_url=%s\n' "$ci_run_url"
    printf 'ci_run_attempt=%s\n' "$ci_run_attempt"
    printf 'release_set=%s\n' "$release_set"
  } >>"$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### Release gate passed\n\n'
    printf -- '- Source: `%s`\n' "$source_sha"
    printf -- '- Remote `main`: `%s`\n' "$main_sha"
    printf -- '- CI: [%s](%s), attempt `%s`, job `Check` successful\n' \
      "$ci_run_id" "$ci_run_url" "$ci_run_attempt"
    printf -- '- Registry release plan: `%s`\n' "$registry_release_set"
  } >>"$GITHUB_STEP_SUMMARY"
fi
