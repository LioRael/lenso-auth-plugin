#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-set.sh
source "$SCRIPT_DIR/release-set.sh"

fail() {
  echo "::error title=Release postcondition::$*" >&2
  exit 1
}

for variable in GITHUB_TOKEN GITHUB_REPOSITORY GITHUB_REF GITHUB_EVENT_NAME RELEASE_SHA EXPECTED_RELEASE_SET RELEASE_ACTION_OUTCOME; do
  [[ -n "${!variable:-}" ]] || fail "missing required environment variable: $variable"
done
[[ "$GITHUB_REPOSITORY" == "LioRael/lenso-auth-plugin" ]] || fail "unexpected repository"
[[ "$GITHUB_REF" == "refs/heads/main" && "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]] ||
  fail "release postcondition requires a manual main workflow"
[[ "${RELEASE_MODE:-}" == "publish" && "${RELEASE_CONFIRMATION:-}" == "publish" ]] ||
  fail "release postcondition requires confirmed publish mode"

source_sha="${RELEASE_SHA,,}"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "source_sha must be a full commit SHA"
expected="$(release_set_canonical "$EXPECTED_RELEASE_SET")" || fail "invalid approved release_set"
[[ "$expected" != "[]" ]] || fail "approved release_set must be non-empty"

actual='[]'
output_valid=true
raw_actual="${ACTUAL_RELEASES:-}"
if [[ -z "$raw_actual" || "$raw_actual" == "null" ]]; then
  output_valid=false
elif ! actual="$(release_releases_canonical "$raw_actual" 2>/dev/null)"; then
  actual='[]'
  output_valid=false
fi

tags_match=true
if [[ "$output_valid" == true ]]; then
  while IFS=$'\t' read -r package version tag; do
    if [[ "$tag" != "${package}@${version}" ]]; then
      printf 'release-plz output tag %s does not match approved tag %s@%s\n' \
        "$tag" "$package" "$version" >&2
      tags_match=false
    fi
  done < <(jq -r '.[] | [.package_name, .version, (.tag // "")] | @tsv' <<<"$raw_actual")
fi

remote_tag_commit() {
  local tag="$1"
  local payload object_type object_sha depth
  payload="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" 2>/dev/null)" || return 1
  for ((depth = 0; depth < 5; depth++)); do
    object_type="$(jq -er '.object.type | select(. == "commit" or . == "tag")' <<<"$payload")" || return 1
    object_sha="$(jq -er '.object.sha | select(test("^[0-9a-fA-F]{40}$"))' <<<"$payload")" || return 1
    if [[ "$object_type" == commit ]]; then
      printf '%s\n' "${object_sha,,}"
      return 0
    fi
    payload="$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/${object_sha}" 2>/dev/null)" || return 1
  done
  return 1
}

observed_ok=true
printf 'Approved release_set: %s\n' "$expected"
printf 'Release-plz reported: %s\n' "$actual"
while IFS=$'\t' read -r package version; do
  registry_status="$(
    curl --silent --show-error --location --retry 2 --max-time 20 \
      --user-agent 'Lenso-release-postcondition/1.0 (https://github.com/LioRael/lenso-auth-plugin)' \
      --output /dev/null --write-out '%{http_code}' \
      "https://crates.io/api/v1/crates/${package}/${version}"
  )" || registry_status='request_failed'
  if [[ "$registry_status" != 200 ]]; then
    printf '%s@%s is not visible on crates.io (HTTP %s)\n' "$package" "$version" "$registry_status" >&2
    observed_ok=false
  fi

  tag="${package}@${version}"
  if tag_sha="$(remote_tag_commit "$tag")"; then
    if [[ "$tag_sha" != "$source_sha" ]]; then
      printf 'tag %s does not point to approved source_sha: observed %s, expected %s\n' \
        "$tag" "$tag_sha" "$source_sha" >&2
      observed_ok=false
    fi
  else
    tag_sha='unavailable'
    printf 'tag %s has no verifiable commit target\n' "$tag" >&2
    observed_ok=false
  fi

  release_state='unavailable'
  if release_payload="$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" 2>/dev/null)"; then
    if jq -e --arg tag "$tag" '
      .tag_name == $tag
      and (.name | type == "string")
      and (.name | length > 0)
      and .draft == false
      and .prerelease == false
    ' <<<"$release_payload" >/dev/null; then
      release_state='published'
    else
      release_state='invalid'
      printf 'GitHub Release for %s is not a published, non-prerelease release with the approved tag and a name\n' \
        "$tag" >&2
      observed_ok=false
    fi
  else
    printf 'GitHub Release for %s is not visible\n' "$tag" >&2
    observed_ok=false
  fi
  printf '%s@%s: registry HTTP %s, remote tag commit %s, GitHub Release %s\n' \
    "$package" "$version" "$registry_status" "$tag_sha" "$release_state"
done < <(jq -r '.[] | [.package_name, .version] | @tsv' <<<"$expected")

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### Auth release postcondition\n\n'
    printf -- '- Approved source: `%s`\n' "$source_sha"
    printf -- '- Approved release set: `%s`\n' "$expected"
    printf -- '- Release-plz reported: `%s`\n' "$actual"
    printf -- '- Action outcome: `%s`\n' "$RELEASE_ACTION_OUTCOME"
    printf -- '- Registry, tag, and GitHub Release observations: see this step log.\n'
  } >>"$GITHUB_STEP_SUMMARY"
fi

[[ "$output_valid" == true ]] || fail "release-plz output is missing or invalid; inspect registry and tag observations before any retry"
[[ "$tags_match" == true ]] || fail "release-plz output includes an unapproved tag"
[[ "$RELEASE_ACTION_OUTCOME" == success ]] ||
  fail "release-plz action did not succeed; inspect registry and tag observations before any retry"
[[ "$actual" == "$expected" ]] ||
  fail "release-plz output does not match approved release_set: reported ${actual}, expected ${expected}; inspect partial publication before any retry"
[[ "$observed_ok" == true ]] || fail "registry, tag, or GitHub Release readback failed; do not claim completed publication"
printf 'Auth release postcondition passed for %s and %s\n' "$source_sha" "$expected"
