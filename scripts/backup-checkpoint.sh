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

mkdir -p -- "$repository_path"
chmod 0700 -- "$repository_path"
checkpoint_directory=$(mktemp -d "${TMPDIR:-/tmp}/facets-node-checkpoint.XXXXXX")
restore_placeholder=$(mktemp -d "${TMPDIR:-/tmp}/facets-node-restore-placeholder.XXXXXX")
chmod 0700 -- "$checkpoint_directory" "$restore_placeholder"

export FACETS_NODE_BACKUP_REPOSITORY=$repository_path
export FACETS_NODE_BACKUP_PASSWORD_FILE=$password_file
export FACETS_NODE_CHECKPOINT_DIRECTORY=$checkpoint_directory
export FACETS_NODE_RESTORE_DIRECTORY=$restore_placeholder
export FACETS_NODE_CHECKPOINT_REVISION
FACETS_NODE_CHECKPOINT_REVISION=$(git rev-parse --verify HEAD 2>/dev/null || printf unknown)

compose=(docker compose -f compose.yaml -f compose.backup.yaml)
source_was_running=false
if [[ -n $("${compose[@]}" ps --status running -q node) ]]; then
  source_was_running=true
fi

restart_source() {
  if [[ $source_was_running == true ]]; then
    "${compose[@]}" up -d node >/dev/null
    source_ready=false
    for _ in {1..30}; do
      if curl --fail --silent \
        "http://127.0.0.1:${FACETS_NODE_PUBLISHED_PORT:-8080}/readyz" \
        >/dev/null; then
        source_ready=true
        break
      fi
      sleep 1
    done
    [[ $source_ready == true ]] || {
      echo "source Facets Node did not become ready after checkpoint" >&2
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
  "${compose[@]}" stop node >/dev/null
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
  --host facets-node \
  --tag facets-node-checkpoint \
  --exclude /blobs/.staging \
  /checkpoint /blobs

restart_source
"${compose[@]}" run --rm --no-deps repository check
"${compose[@]}" run --rm --no-deps repository snapshots \
  --host facets-node \
  --tag facets-node-checkpoint \
  --latest 1
