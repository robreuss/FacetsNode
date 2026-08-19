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
published_port=${4:-18082}

[[ $repository_path == /* && -d $repository_path ]] || usage
[[ $password_file == /* && -f $password_file && -r $password_file ]] || usage
[[ $target_project =~ ^[a-z0-9][a-z0-9_-]*$ ]] || usage
[[ $target_project != facets-shared-spaces ]] || {
  echo "restore target must be a new Compose project, not facets-shared-spaces" >&2
  exit 65
}
[[ $published_port =~ ^[0-9]+$ && $published_port -ge 1024 && $published_port -le 65535 ]] || usage

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
deployment_directory=$(cd -- "$script_directory/.." && pwd)
cd -- "$deployment_directory"

restore_directory=$(mktemp -d "${TMPDIR:-/tmp}/facets-shared-spaces-restore.XXXXXX")
checkpoint_placeholder=$(mktemp -d "${TMPDIR:-/tmp}/facets-shared-spaces-checkpoint-placeholder.XXXXXX")
chmod 0700 -- "$restore_directory" "$checkpoint_placeholder"

export FACETS_SHARED_SPACES_BACKUP_REPOSITORY=$repository_path
export FACETS_SHARED_SPACES_BACKUP_PASSWORD_FILE=$password_file
export FACETS_SHARED_SPACES_CHECKPOINT_DIRECTORY=$checkpoint_placeholder
export FACETS_SHARED_SPACES_RESTORE_DIRECTORY=$restore_directory
export FACETS_SHARED_SPACES_MANAGEMENT_PORT=$published_port

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
  if docker volume inspect "${target_project}_facets-shared-spaces-${volume_name}" >/dev/null 2>&1; then
    echo "restore target volume already exists: ${target_project}_facets-shared-spaces-${volume_name}" >&2
    exit 65
  fi
done

"${compose[@]}" run --rm --no-deps repository restore latest \
  --host facets-shared-spaces \
  --tag facets-shared-spaces-checkpoint \
  --target /restore
"${compose[@]}" run --rm --no-deps checkpoint-verify

"${compose[@]}" up -d postgres >/dev/null
database_ready=false
for _ in {1..30}; do
  if "${compose[@]}" exec -T postgres pg_isready -U facets_shared_spaces -d facets_shared_spaces >/dev/null 2>&1; then
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
"${compose[@]}" up -d server >/dev/null

server_ready=false
for _ in {1..30}; do
  if curl --fail --silent "http://127.0.0.1:${published_port}/readyz" >/dev/null; then
    server_ready=true
    break
  fi
  sleep 1
done
[[ $server_ready == true ]] || {
  echo "restored Facets Shared Spaces Server did not become ready" >&2
  exit 1
}

echo "restored checkpoint into project $target_project at http://127.0.0.1:${published_port}"
