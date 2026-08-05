#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 /absolute/restic-repository /absolute/restic-password-file new-project-name [published-port]" >&2
  exit 64
}

[[ $# -ge 3 && $# -le 4 ]] || usage
repository_path=$1
password_file=$2
target_project=$3
published_port=${4:-18081}

[[ $repository_path == /* && -d $repository_path ]] || usage
[[ $password_file == /* && -f $password_file && -r $password_file ]] || usage
[[ $target_project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ $target_project != facets-node ]] || {
  echo "restore target must be a new Compose project, not facets-node" >&2
  exit 65
}
[[ $published_port =~ ^[0-9]+$ && $published_port -ge 1024 && $published_port -le 65535 ]] || usage

restore_directory=$(mktemp -d "${TMPDIR:-/tmp}/facets-node-restore.XXXXXX")
checkpoint_placeholder=$(mktemp -d "${TMPDIR:-/tmp}/facets-node-checkpoint-placeholder.XXXXXX")
chmod 0700 -- "$restore_directory" "$checkpoint_placeholder"

export FACETS_NODE_BACKUP_REPOSITORY=$repository_path
export FACETS_NODE_BACKUP_PASSWORD_FILE=$password_file
export FACETS_NODE_CHECKPOINT_DIRECTORY=$checkpoint_placeholder
export FACETS_NODE_RESTORE_DIRECTORY=$restore_directory
export FACETS_NODE_PUBLISHED_PORT=$published_port

compose=(docker compose -p "$target_project" -f compose.yaml -f compose.backup.yaml)

cleanup() {
  "${compose[@]}" run --rm --no-deps temporary-cleanup >/dev/null 2>&1 || true
  rmdir -- "$restore_directory" "$checkpoint_placeholder" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n $("${compose[@]}" ps -aq) ]]; then
  echo "restore target already has Compose containers: $target_project" >&2
  exit 65
fi
for volume_name in postgres blobs; do
  if docker volume inspect "${target_project}_facets-node-${volume_name}" >/dev/null 2>&1; then
    echo "restore target volume already exists: ${target_project}_facets-node-${volume_name}" >&2
    exit 65
  fi
done

"${compose[@]}" run --rm --no-deps repository restore latest \
  --host facets-node \
  --tag facets-node-checkpoint \
  --target /restore
"${compose[@]}" run --rm --no-deps checkpoint-verify

"${compose[@]}" up -d postgres >/dev/null
database_ready=false
for _ in {1..30}; do
  if "${compose[@]}" exec -T postgres pg_isready -U facets -d facets >/dev/null 2>&1; then
    database_ready=true
    break
  fi
  sleep 1
done
[[ $database_ready == true ]] || {
  echo "restored PostgreSQL did not become ready" >&2
  exit 1
}

"${compose[@]}" run --rm --no-deps restore-database
"${compose[@]}" run --rm --no-deps restore-blobs
"${compose[@]}" up -d node >/dev/null

node_ready=false
for _ in {1..30}; do
  if curl --fail --silent "http://127.0.0.1:${published_port}/readyz" >/dev/null; then
    node_ready=true
    break
  fi
  sleep 1
done
[[ $node_ready == true ]] || {
  echo "restored Facets Node did not become ready" >&2
  exit 1
}

echo "restored checkpoint into project $target_project at http://127.0.0.1:${published_port}"
