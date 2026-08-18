#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 /absolute/restic-repository /absolute/restic-password-file" >&2
  exit 64
}

[[ $# -eq 2 ]] || usage
repository_path=$1
password_file=$2
[[ $repository_path == /* ]] || usage
[[ $password_file == /* && -f $password_file && -r $password_file ]] || usage

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=revision-attestation.sh
source "$script_directory/revision-attestation.sh"

mkdir -p -- "$repository_path"
chmod 0700 -- "$repository_path"
checkpoint_directory=$(mktemp -d "${TMPDIR:-/tmp}/facets-device-sync-checkpoint.XXXXXX")
restore_placeholder=$(mktemp -d "${TMPDIR:-/tmp}/facets-device-sync-restore-placeholder.XXXXXX")
chmod 0700 -- "$checkpoint_directory" "$restore_placeholder"

export FACETS_DEVICE_SYNC_BACKUP_REPOSITORY=$repository_path
export FACETS_DEVICE_SYNC_BACKUP_PASSWORD_FILE=$password_file
export FACETS_DEVICE_SYNC_CHECKPOINT_DIRECTORY=$checkpoint_directory
export FACETS_DEVICE_SYNC_RESTORE_DIRECTORY=$restore_placeholder
export FACETS_DEVICE_SYNC_CHECKPOINT_REVISION
FACETS_DEVICE_SYNC_CHECKPOINT_REVISION=$(facets_device_sync_resolve_checkpoint_revision)

compose=(docker compose -f compose.yaml -f compose.backup.yaml)
source_was_running=false
if [[ -n $("${compose[@]}" ps --status running -q server) ]]; then
  source_was_running=true
fi

restart_source() {
  if [[ $source_was_running == true ]]; then
    "${compose[@]}" up -d server >/dev/null
    source_ready=false
    for _ in {1..30}; do
      if curl --fail --silent \
        "http://127.0.0.1:${FACETS_DEVICE_SYNC_MANAGEMENT_PORT:-8080}/readyz" \
        >/dev/null; then
        source_ready=true
        break
      fi
      sleep 1
    done
    [[ $source_ready == true ]] || {
      echo "source Facets Device Sync Server did not become ready after checkpoint" >&2
      return 1
    }
    source_was_running=false
  fi
}

cleanup() {
  restart_source || true
  "${compose[@]}" run --rm --no-deps temporary-cleanup >/dev/null 2>&1 || true
  rmdir -- "$checkpoint_directory" "$restore_placeholder" 2>/dev/null || true
}
trap cleanup EXIT

if [[ $source_was_running == true ]]; then
  "${compose[@]}" stop server >/dev/null
fi

"${compose[@]}" run --rm --no-deps checkpoint-database
"${compose[@]}" run --rm --no-deps checkpoint-manifest

if [[ ! -f $repository_path/config ]]; then
  if find "$repository_path" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    echo "backup repository is nonempty but is not a Restic repository" >&2
    exit 65
  fi
  "${compose[@]}" run --rm --no-deps repository init
fi

"${compose[@]}" run --rm --no-deps repository backup \
  --host facets-device-sync \
  --tag facets-device-sync-checkpoint \
  --exclude /blobs/.staging \
  /checkpoint /blobs

restart_source
"${compose[@]}" run --rm --no-deps repository check
"${compose[@]}" run --rm --no-deps repository snapshots \
  --host facets-device-sync \
  --tag facets-device-sync-checkpoint \
  --latest 1
