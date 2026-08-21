#!/usr/bin/env bash

# Runs the opt-in Swift <-> Go Device Sync enrollment gate against a real
# Device Sync service. The Go integration test provisions one fresh principal
# and writes sponsor-only transport authority to a mode-0600 temporary file.
# The Swift test consumes that file once, exercises PIN handoff plus device
# admission, and removes the file before returning.
#
# Required environment:
#   FACETS_SERVER_TEST_BASE_URL
#   FACETS_SERVER_TEST_OPERATOR_TOKEN
#
# Optional environment:
#   FACETS_SWIFT_REPOSITORY      Defaults to the sibling ../Facets checkout.

set -euo pipefail

required_environment=(
  FACETS_SERVER_TEST_BASE_URL
  FACETS_SERVER_TEST_OPERATOR_TOKEN
)

for variable_name in "${required_environment[@]}"; do
  if [[ -z "${!variable_name:-}" ]]; then
    printf 'error: %s is required\n' "$variable_name" >&2
    exit 64
  fi
done

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
swift_repository="${FACETS_SWIFT_REPOSITORY:-$repository_root/../Facets}"
swift_package="$swift_repository/Packages/FacetsDeveloperKit"

if [[ ! -f "$swift_package/Package.swift" ]]; then
  printf 'error: FacetsDeveloperKit was not found at %s\n' "$swift_package" >&2
  printf 'set FACETS_SWIFT_REPOSITORY to the Facets checkout\n' >&2
  exit 66
fi

access_directory="$(mktemp -d "${TMPDIR:-/tmp}/facets-device-sync-enrollment.XXXXXX")"
access_path="$access_directory/access.json"

cleanup() {
  rm -f "$access_path"
  rmdir "$access_directory" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

umask 077

printf '%s\n' 'Provisioning a fresh one-time Device Sync enrollment descriptor…'
FACETS_SERVER_TEST_SWIFT_ENROLLMENT_ACCESS_OUTPUT_PATH="$access_path" \
  go test ./integration \
    -run '^TestLiveProvisionSwiftDeviceSyncEnrollmentAccess$' \
    -count=1

if [[ ! -f "$access_path" ]]; then
  printf '%s\n' 'error: server did not create the Swift enrollment descriptor' >&2
  exit 70
fi

permissions="$(stat -f '%Lp' "$access_path")"
if [[ "$permissions" != '600' ]]; then
  printf 'error: enrollment descriptor has unsafe permissions %s\n' "$permissions" >&2
  exit 77
fi

printf '%s\n' 'Running the Swift client against the live Device Sync service…'
FACETS_SERVER_TEST_SWIFT_ENROLLMENT_ACCESS_PATH="$access_path" \
  swift test --package-path "$swift_package" \
    --filter 'DeviceSyncLiveEnrollmentTests/testLiveDeviceSyncEnrollmentMailboxAndAdmission'

if [[ -e "$access_path" ]]; then
  printf '%s\n' 'error: Swift did not consume and remove the enrollment descriptor' >&2
  exit 70
fi

printf '%s\n' 'Swift <-> Go Device Sync enrollment gate passed.'
