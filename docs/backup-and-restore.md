# Coordinated encrypted backup and restore

Facets Node's PostgreSQL database and opaque blob volume are one recovery unit.
The database holds authority and quota facts for the filesystem bytes, so a
backup of either side alone is invalid.

The first self-hosted operations profile creates a quiesced PostgreSQL custom
dump and snapshots that dump, its manifest, and the exact blob tree into an
encrypted Restic repository. The Node process is stopped during capture so no
writer can cross the database/blob checkpoint boundary; PostgreSQL remains
running. The script restarts the Node and requires `/readyz` before reporting
success.

The operations image is pinned by tag and multi-platform image digest. Updating
it requires review of the [official Restic releases](https://github.com/restic/restic/releases)
and a complete backup/restore drill; it is not advanced implicitly by a floating
container tag.

This initial wrapper targets a local filesystem path. For real disaster
recovery, that path must be a separately protected and monitored mount or be
copied to off-host storage. A repository on the same system disk is only a
restore test, not a disaster-recovery backup. The repository password is not
stored in the repository or snapshot. Preserve it separately; loss of that
password makes the backup unrecoverable.

## Create a checkpoint

Generate a dedicated password file outside the repository, then pass absolute
paths:

```sh
install -d -m 0700 /srv/facets-node-backup
openssl rand -base64 48 > /secure/location/facets-node-restic-password
chmod 0600 /secure/location/facets-node-restic-password

FACETS_NODE_CHECKPOINT_REVISION=<40-character-committed-revision> \
  ./scripts/backup-checkpoint.sh \
  /srv/facets-node-backup \
  /secure/location/facets-node-restic-password
```

The first run initializes the repository. Later runs add deduplicated snapshots
tagged `facets-node-checkpoint`. The script refuses a nonempty directory that
is not already a Restic repository. It also refuses to capture while an
interrupted blob remains in the staging directory. Temporary plaintext dump
and manifest files live in a mode-0700 `mktemp` directory and are removed by a
network-disabled operations container after the snapshot.

Run the command from the repository root with the same `.env` used by the
source stack. Expect a bounded service interruption whose duration depends on
database and blob size. Retention pruning is deliberately not automated yet;
adopt and test a retention policy before scheduling unattended backups.

`FACETS_NODE_CHECKPOINT_REVISION` takes precedence over local Git state and
must be a full 40-character lowercase commit ID when supplied. This is required
for the source-copy deployment, whose directory intentionally may not contain
`.git`. The script rejects malformed explicit values rather than recording a
misleading revision. If the variable is absent, it uses the current Git commit
when available and otherwise records `unknown`. Use the same revision embedded
in the running image's `org.opencontainers.image.revision` label. Do not keep a
mutable revision marker beside the deployment: the explicit manifest value,
immutable image label, running image ID, and source-tree checksum are the
attestation chain.

## Restore without overwriting the source

Restore always requires a new Compose project name. The script rejects the
canonical `facets-node` project and any target that already has containers or
database/blob volumes:

```sh
./scripts/restore-checkpoint.sh \
  /srv/facets-node-backup \
  /secure/location/facets-node-restic-password \
  facets-node-recovery-20260805 \
  18081
```

Restic authenticates and decrypts the latest tagged checkpoint into a temporary
directory. The operation then verifies the database dump checksum and the
complete sorted blob digest inventory before it creates a fresh PostgreSQL
volume, restores the database in one transaction, copies blobs into a fresh
blob volume, restores the unprivileged runtime ownership declared by the Node
image, and starts that same image on the requested loopback port. The source
stack is never a restore target.

After verifying the recovered service, an operator can switch ingress or move
the recovered volumes according to a reviewed incident plan. A fresh deployment
may use new PostgreSQL and operator credentials in its `.env`; relay member,
admission, and domain-administration digests are application data and remain
unchanged. Do not expose both stacks through public ingress simultaneously.

If restore fails after target resources have been created, the script leaves
the isolated target project in place for diagnosis. Remove it only after the
exact project name has been confirmed:

```sh
docker compose -p facets-node-recovery-20260805 -f compose.yaml down --volumes
```

That command irreversibly removes only the named recovery stack and its fresh
volumes. It does not delete the Restic repository.

## Current proof boundary

The first persistent Proxmox drill restored an encrypted snapshot into a new
Compose project on the same VM. Source and recovery stacks reported identical
counts for every pairing/relay authority table, identical sorted blob paths and
digests, and healthy private endpoints. The temporary decrypted tree was also
removed successfully.

The authority-lifecycle checkpoint repeated the isolated restore with retained
credential rotations present and matched rotation, admission, and audit counts
before removing the temporary recovery resources.

Still required before production are a fresh-VM/off-host restore drill,
scheduled repository integrity checks, a versioned retention/pruning policy,
capacity and duration measurements at realistic data size, credential-rotation
drills (including operator provisioning), ingress-switch procedures,
monitoring, and a point-in-time recovery policy.
