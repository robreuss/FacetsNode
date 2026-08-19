# Shared Spaces coordinated backup and restore

Facets Shared Spaces Server's PostgreSQL database and opaque blob volume form
one recovery unit. PostgreSQL holds Space authority, participant state, relay
custody, key-grant ciphertext, quotas, receipts, and references to the encrypted
blob bytes. A backup of only the database or only the blob volume is invalid.

The checked-in operations profile stops only the Shared Spaces server writer,
creates a PostgreSQL custom dump, inventories the exact non-staging blob tree,
and stores both in an encrypted Restic snapshot. PostgreSQL remains running
during capture. The script restarts the server and requires `/readyz` before it
reports success.

This is operationally independent from Device Sync. It uses the Shared Spaces
Compose project, database, credentials, blob volume, source revision, Restic
host, and snapshot tag. Running a backup never reads or stops Device Sync.

## Create a checkpoint

Prepare a password file separately from the repository and run the script from
any directory:

```sh
install -d -m 0700 /srv/facets-shared-spaces-backup
openssl rand -base64 48 > /secure/location/facets-shared-spaces-restic-password
chmod 0600 /secure/location/facets-shared-spaces-restic-password

FACETS_SHARED_SPACES_CHECKPOINT_REVISION=<40-character-committed-revision> \
  ./deploy/shared-spaces/scripts/backup-checkpoint.sh \
  /srv/facets-shared-spaces-backup \
  /secure/location/facets-shared-spaces-restic-password
```

The deployment's `deploy/shared-spaces/.env` supplies the PostgreSQL secret.
The first run initializes the Restic repository; later runs create deduplicated
snapshots tagged `facets-shared-spaces-checkpoint`. The script rejects a
nonempty path that is not a Restic repository and refuses to capture while an
interrupted blob remains in `.staging`.

Temporary plaintext dump and manifest files use mode-0700 `mktemp`
directories. A network-disabled operations container removes them after the
snapshot. The Restic password is not stored in the repository or snapshot and
must be preserved separately.

When explicitly supplied, `FACETS_SHARED_SPACES_CHECKPOINT_REVISION` must be a
full lowercase 40-character Git commit ID. When absent, the script records the
current Git commit if available and otherwise `unknown`. Production checkpoints
must use the revision embedded in the running image's
`org.opencontainers.image.revision` label.

## Restore into a fresh project

Restore is deliberately unable to overwrite the canonical
`facets-shared-spaces` project. It rejects any target project with existing
containers or PostgreSQL/blob volumes:

```sh
./deploy/shared-spaces/scripts/restore-checkpoint.sh \
  /srv/facets-shared-spaces-backup \
  /secure/location/facets-shared-spaces-restic-password \
  facets-shared-spaces-recovery-20260818 \
  18082
```

Restic authenticates and decrypts the latest Shared Spaces checkpoint into a
temporary directory. The workflow verifies the database checksum and complete
sorted blob digest inventory before creating fresh volumes, restoring the
database in one transaction, restoring the blob tree and unprivileged runtime
ownership, and starting the recovered server on the requested loopback port.
It does not start public ingress.

After independent authority, relay, key-grant, and blob verification, an
operator may switch ingress using a reviewed incident procedure. Do not expose
the source and recovered Shared Spaces stacks publicly at the same time.

If a restore fails after resources have been created, the isolated target is
left for diagnosis. Remove it only after confirming its exact project name:

```sh
docker compose -p facets-shared-spaces-recovery-20260818 \
  -f deploy/shared-spaces/compose.yaml down --volumes
```

This removes only the fresh recovery stack. It does not remove the encrypted
Restic repository.

## Verification boundary

The ordinary Go suite verifies the independent configuration namespaces,
Shared Spaces database/blob bindings, revision rules, restore target guards,
and shell syntax. It does not claim a real backup drill. Before production,
run an exact-image backup and fresh-host restore, compare every Shared Spaces
authority and relay table plus every blob digest, test key-grant retrieval and
participant revocation after recovery, measure realistic duration/capacity,
and adopt monitored off-host retention and pruning.
