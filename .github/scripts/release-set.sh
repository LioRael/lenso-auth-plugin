#!/usr/bin/env bash
set -euo pipefail

release_set_canonical() {
  jq -e -c '
    def valid_package_name:
      type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_-]*$");
    def valid_version:
      type == "string"
      and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$");
    . as $set
    | if (
        ($set | type) == "array"
        and ($set | all(.[];
          type == "object"
          and ((keys | sort) == ["package_name", "version"])
          and (.package_name | valid_package_name)
          and (.version | valid_version)
        ))
        and (($set | map(.package_name) | length)
          == ($set | map(.package_name) | unique | length))
      )
      then ($set | sort_by(.package_name))
      else error("release_set must be a unique package_name/version array")
      end
  ' <<<"$1"
}

release_releases_canonical() {
  jq -e -c '
    def valid_package_name:
      type == "string" and test("^[A-Za-z0-9][A-Za-z0-9_-]*$");
    def valid_version:
      type == "string"
      and test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$");
    . as $releases
    | if (
        ($releases | type) == "array"
        and ($releases | all(.[];
          type == "object"
          and (.package_name | valid_package_name)
          and (.version | valid_version)
        ))
      )
      then ($releases | map({package_name, version}) | sort_by(.package_name))
      else error("release-plz output must contain package_name/version objects")
      end
  ' <<<"$1"
}
