# High-volume checkpoint and restart acceptance

This opt-in live gate proves that a running Node can cross the former 10,000
message boundary, collect in bounded batches, bootstrap a replacement
subscription from an activated checkpoint, and continue delivery after the
Node and PostgreSQL containers are recreated. It uses the real HTTP,
PostgreSQL, filesystem-upload, fence, and checkpoint paths. It is not part of
ordinary `go test ./...`.

The prepare phase:

1. provisions a domain with a 20,000-message quota;
2. publishes, pages, and custody-acknowledges 10,050 opaque messages, alternating
   acknowledgments between two agents on one subscription;
3. acquires a checkpoint fence, resumably uploads a multi-chunk retained blob,
   and publishes three quarantined checkpoint messages;
4. proves quarantine before activation and complete suffix visibility after it;
5. collects exactly 10,000 messages, obtains a fresh plan digest, collects the
   remaining 50, and proves exact retries for both batches;
6. creates a replacement subscription at the checkpoint boundary, proves
   retained-snapshot and subsequent-mutation delivery, and checks tenant/domain
   counters, reservations, oldest cursor, and checkpoint state; and
7. writes the credentials needed by the verify phase to one explicitly named,
   newly created mode-0600 file outside the repository.

The gate never creates a state file implicitly, never overwrites one, and
rejects repository-relative or repository-contained paths. That file contains
test bearer credentials. Keep its parent directory mode 0700, do not copy it
into a Docker build context, and remove it after the verify phase.

## Prepare

Run against a disposable deployment. The scenario makes more than 20,000 relay
message-surface requests. For this gate only, set the following Node/Compose
overrides before recreating the Node container:

```sh
FACETS_NODE_TRAFFIC_RELAY_MESSAGE_RATE_PER_MINUTE=60000
FACETS_NODE_TRAFFIC_RELAY_MESSAGE_BURST=10000
FACETS_NODE_TRAFFIC_RELAY_MESSAGE_CONNECTION_RATE_PER_MINUTE=60000
FACETS_NODE_TRAFFIC_RELAY_MESSAGE_CONNECTION_BURST=10000
```

These are the documented bounded operator controls, not a product bypass. The
test retries `429` only when
`FACETS_NODE_TEST_HIGH_VOLUME_RETRY_429=1` is explicitly set, requires an
integer `Retry-After`, and gives up after two minutes for any one request.
Restore normal hosted limits after the gate.

Choose a new path that does not exist yet:

```sh
STATE_DIRECTORY="$(mktemp -d /tmp/facets-node-high-volume.XXXXXX)"
chmod 700 "$STATE_DIRECTORY"
STATE_PATH="$STATE_DIRECTORY/state.json"

FACETS_NODE_TEST_HIGH_VOLUME=1 \
FACETS_NODE_TEST_HIGH_VOLUME_PHASE=prepare \
FACETS_NODE_TEST_HIGH_VOLUME_RETRY_429=1 \
FACETS_NODE_TEST_HIGH_VOLUME_STATE_PATH="$STATE_PATH" \
FACETS_NODE_TEST_BASE_URL='http://127.0.0.1:8080' \
FACETS_NODE_TEST_OPERATOR_TOKEN='<private operator token>' \
go test ./integration \
  -run '^TestLiveReplicaRelayHighVolumeCheckpointRestart$' \
  -count=1 -timeout=30m -v

test "$(stat -f '%Lp' "$STATE_PATH")" = 600
```

The prepare URL must reach the private management ingress because public Caddy
correctly denies operator tenant provisioning. Use an authenticated management
tunnel for an off-host Node; do not expose the plaintext management listener.

## Recreate and verify

Recreate containers without deleting or replacing the PostgreSQL and blob
volumes, then wait for readiness. For Compose:

```sh
docker compose up -d --force-recreate postgres node ingress
docker compose ps
curl --fail --silent http://127.0.0.1:8080/readyz

FACETS_NODE_TEST_HIGH_VOLUME=1 \
FACETS_NODE_TEST_HIGH_VOLUME_PHASE=verify \
FACETS_NODE_TEST_HIGH_VOLUME_RETRY_429=1 \
FACETS_NODE_TEST_HIGH_VOLUME_STATE_PATH="$STATE_PATH" \
FACETS_NODE_TEST_BASE_URL='http://127.0.0.1:8080' \
go test ./integration \
  -run '^TestLiveReplicaRelayHighVolumeCheckpointRestart$' \
  -count=1 -timeout=10m -v
```

The verify phase does not use an operator token and does not reprovision. It
authenticates with the saved tenant/domain/member authorities, checks the
activated checkpoint and retained blob, publishes a new opaque mutation, fetches
it from the replacement subscription, and custody-acknowledges it.

After recording the result, remove the credential state and restore the normal
traffic settings:

```sh
rm "$STATE_PATH"
rmdir "$STATE_DIRECTORY"
```

Container recreation is not a backup/restore proof. The coordinated
backup/restore procedure remains a separate gate in
[`backup-and-restore.md`](backup-and-restore.md).
