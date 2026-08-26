#!/usr/bin/env bash

# Runs the opt-in Swift <-> Go Shared Spaces initial-authority gate against a
# disposable pinned-TLS FacetsNode handler. The Go side publishes a short-lived
# deployment offer and disposable operator bearer to a mode-0600 file. Swift
# authenticates the physical deployment before releasing that bearer, creates
# one fresh Shared Space, and proves an ordinary authority-bound status read.
#
# Optional environment:
#   FACETS_SWIFT_REPOSITORY      Defaults to the sibling ../Facets checkout.

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
swift_repository="${FACETS_SWIFT_REPOSITORY:-$repository_root/../Facets}"
swift_package="$swift_repository/Packages/FacetsDeveloperKit"

if [[ ! -f "$swift_package/Package.swift" ]]; then
  printf 'error: FacetsDeveloperKit was not found at %s\n' "$swift_package" >&2
  printf 'set FACETS_SWIFT_REPOSITORY to the Facets checkout\n' >&2
  exit 66
fi

gate_directory="$(mktemp -d "${TMPDIR:-/tmp}/facets-shared-spaces-authority.XXXXXX")"
access_path="$gate_directory/access.json"
result_path="$gate_directory/result.json"
go_log_path="$gate_directory/go-test.log"
go_pid=''

cleanup() {
  if [[ -n "$go_pid" ]] && kill -0 "$go_pid" 2>/dev/null; then
    kill "$go_pid" 2>/dev/null || true
    wait "$go_pid" 2>/dev/null || true
  fi
  rm -f "$access_path" "$result_path" "$go_log_path"
  rmdir "$gate_directory" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

umask 077

printf '%s\n' 'Starting the disposable pinned-TLS Shared Spaces service…'
(
  cd "$repository_root"
  FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_ACCESS_OUTPUT_PATH="$access_path" \
  FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_RESULT_PATH="$result_path" \
    go test ./integration \
      -run '^TestLiveServeSwiftSharedSpacesAuthority$' \
      -count=1 -v
) >"$go_log_path" 2>&1 &
go_pid=$!

for _ in $(seq 1 400); do
  if [[ -f "$access_path" ]]; then
    break
  fi
  if ! kill -0 "$go_pid" 2>/dev/null; then
    wait "$go_pid" || true
    cat "$go_log_path" >&2
    exit 70
  fi
  sleep 0.025
done

if [[ ! -f "$access_path" ]]; then
  printf '%s\n' 'error: Go did not create the Shared Spaces live descriptor' >&2
  cat "$go_log_path" >&2
  exit 70
fi

permissions="$(stat -f '%Lp' "$access_path")"
if [[ "$permissions" != '600' ]]; then
  printf 'error: Shared Spaces descriptor has unsafe permissions %s\n' "$permissions" >&2
  exit 77
fi

printf '%s\n' 'Running the Swift Shared Spaces client against FacetsNode…'
if ! FACETS_SERVER_TEST_SWIFT_SHARED_SPACES_ACCESS_PATH="$access_path" \
  swift test --package-path "$swift_package" \
    --filter 'SharedSpacesLiveProvisioningTests/testLiveInitialAuthorityAndBoundStatusWhenConfigured'; then
  printf '%s\n' 'FacetsNode live-gate log:' >&2
  cat "$go_log_path" >&2
  exit 1
fi

wait "$go_pid"
go_pid=''
cat "$go_log_path"

printf '%s\n' 'Swift <-> Go Shared Spaces authority gate passed.'
