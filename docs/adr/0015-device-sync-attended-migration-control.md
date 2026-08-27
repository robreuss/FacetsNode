# ADR 0015: Device Sync attended migration control

- **Status:** Accepted
- **Scope:** Private operator staging for forward migration and bounded rollback
- **Extends:** ADRs 0006 through 0014

## Decision

The Device Sync binary exposes a private, offline `migration` command. It opens
no listener and requires exclusive custody of the deployment binding registry,
so the ordinary data-plane process must be stopped for every stage. The command
does not create Facets authority. It consumes client-authorized manifests and
complete migration evidence, applies the existing registry/PostgreSQL gates,
and emits canonical JSON for the next attended step.

The stages are:

1. the target signs a short-lived deployment and migration offer;
2. Facets authority signs migration preparation from that offer;
3. the source advances to preparation, fences writes, exports exact state,
   signs the snapshot, and creates a protected forward bundle;
4. an operator moves that directory over an explicitly selected authenticated
   carrier, such as SSH/SCP;
5. the target verifies the complete authority chain, imports the exact standby,
   independently copies and rehashes every ciphertext blob, and signs readiness;
6. Facets authority signs activation from preparation, snapshot, and readiness;
7. both deployments apply the same activation evidence; and
8. if rollback is requested before its signed deadline, the active target
   performs the same sequence in reverse before both sides apply the rollback.

After rollback, the restored source immediately applies a Facets-authorized
`policy_update` settlement successor. This successor changes neither deployment
nor transport policy; it clears the bounded migration state and becomes the
long-lived revision. The rollback Manifest itself expires at the rollback
deadline and is therefore never treated as the final service authority. The
retired replacement is not named by the settlement and cannot install it.

## Portable transfer directory

The source creates a new mode-0700 directory atomically. It contains:

- `bundle.json`, binding the migration direction, signed preparation or
  activation evidence, signed snapshot, trust anchor, initial authority for a
  forward transfer, identifiers, and exact byte totals;
- `service-state.bin`, the canonical logical PostgreSQL artifact;
- `blob-inventory.bin`, the canonical content-addressed blob inventory; and
- `blobs/`, containing every inventoried opaque ciphertext blob at its exact
  tenant/domain/blob identity.

The directory is transport data, not authority. On every open, FacetsNode
rejects symlinks and nonprivate roots, revalidates all signatures and temporal
constraints, rehashes both artifacts, walks the canonical inventory, and
rehashes every blob. The received blob adapter is read-only. Target import then
copies blobs into its own durable store and verifies them again before readiness
can be signed. An existing output path is accepted only as an exact completed
retry; a conflicting or damaged directory fails closed.

The operator chooses the carrier. This checkpoint does not add a public upload,
download, management, or onion endpoint and never silently falls back between
routes. SSH/SCP is appropriate for the development proof. Tor/onion custody and
the client Move Server UI remain separate checkpoints.

## Private control inputs

Every JSON control input must be a regular, nonsymlink file, no larger than
8 MiB, with no group or world permissions. Unknown fields, noncanonical
authority records, trailing data, wrong deployment identities, stale evidence,
and conflicting retries are rejected. The deployment signing key, binding file,
migration custody, PostgreSQL store, and blob root remain distinct durable
inputs.

Registry-first/database-second advancement is intentionally fail-closed for
source preparation and rollback settlement. If the process stops between those
stores, the data plane cannot become ready; an exact retry repairs PostgreSQL
from the same signed manifest. Activation and rollback retain their existing
deployment-signed acceptance journals and startup recovery.

## Rollback meaning and availability

Rollback means moving the complete current Device Sync service state back to
the old deployment. It is not a message undo. The replacement first stops
accepting writes, and the old source remains non-writable until exact reverse
import and client-authorized rollback complete. Target-only messages and blobs
are included in the reverse snapshot.

The rollback deadline bounds admission of the rollback successor. Response-loss
retries of already accepted evidence remain exact and idempotent. Settlement
must first be accepted before the rollback deadline, but its exact completed
retry may repair a lost response later. After the deadline, returning to the old
server is a new forward migration in the opposite direction.

## Verification boundary

The repository gate drives the production control-stage methods across two
independent PostgreSQL databases, deployment signers, binding registries,
custody roots, and blob roots. It proves forward transfer, target-only writes,
reverse transfer, byte-identical semantic database state and blob inventory,
two exact ciphertext blobs, two relay messages, source/target authority states,
retired-target settlement refusal, and expired exact settlement retry.

On 2026-08-27, the same gate passed in two isolated PostgreSQL 17 containers on
the Facets Box development VM. An image built from the exact accepted revision
started the settled original deployment and returned HTTP 200 from `/readyz`.
The retired replacement process failed closed before listening. This is a
same-host, separate-deployment proof; it is not physical two-host failure,
network interruption, onion transfer, Facets UI, or client continuity evidence.
