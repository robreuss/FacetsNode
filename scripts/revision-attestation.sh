#!/usr/bin/env bash

facets_device_sync_resolve_checkpoint_revision() {
  local revision
  if [[ ${FACETS_DEVICE_SYNC_CHECKPOINT_REVISION+x} == x ]]; then
    revision=$FACETS_DEVICE_SYNC_CHECKPOINT_REVISION
    if [[ ! $revision =~ ^[0-9a-f]{40}$ ]]; then
      echo "FACETS_DEVICE_SYNC_CHECKPOINT_REVISION must be a 40-character lowercase Git commit ID" >&2
      return 65
    fi
    printf '%s\n' "$revision"
    return 0
  fi

  if revision=$(git rev-parse --verify 'HEAD^{commit}' 2>/dev/null) &&
    [[ $revision =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s\n' "$revision"
    return 0
  fi

  printf '%s\n' unknown
}
