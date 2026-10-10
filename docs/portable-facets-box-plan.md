# Portable Facets Box implementation plan

Status: active implementation plan, 2026-10-10.

## Outcome and product boundary

Facets Box Desktop (FBD) and a Linux VM hosted by Proxmox are two host adapters
for one containerized Facets Box service appliance. Portability is delivered by
the signed service release, explicit retained-state contract, and tested
restore/relocation procedures. A raw VM image is not the portability unit.

The Box remains content-blind infrastructure. Device Sync and Shared Spaces are
separate services built from common custody, routing, authorization, and
Carriage capabilities; neither service gives the Box plaintext semantic
authority. Device Sync has one Box-mediated protocol path, whether a client is
on the home LAN or away from it. Shared Spaces uses a related publication and
receipt path but retains its own participant, roster, and Space policy.

Identity work is intentionally outside this infrastructure checkpoint. The
current design proposal is a private Principal root, a Box-scoped pseudonymous
account, service-specific grants, and Persona presentation in Shared Spaces;
it is not yet an implemented contract. The exact Principal/Persona and Carriage
contracts are evolving in the active Facets work and will be integrated only
from a reviewed handoff.

## Parallel-work ownership

- The active Facets work owns client-side Carriage and protected Worker
  contracts, Job Custody, Principal/Persona modeling, and app integration.
- This plan owns FacetsNode appliance packaging, architecture-neutral container
  release mechanics, the Proxmox host adapter, and FBD host-adapter alignment.
- Shared contract changes cross the boundary only at explicit checkpoints. This
  avoids file-by-file coordination and lets both efforts progress independently.
- Existing Proxmox VM 190 and its retained Device Sync/Shared Spaces identities
  are reference evidence only. This work must not mutate, clone, or republish
  them.

## Checkpoints

### 1. Portable appliance contract and service release

- Define strict, versioned host profiles for FBD ARM64 and Proxmox AMD64.
- Keep system storage replaceable and authority-bearing data storage retained.
- Make service-kit build, OCI verification, import, and runtime preparation
  architecture-aware for ARM64 and AMD64.
- Keep the FBD foundation builder ARM64-specific; it is a host-adapter concern.
- Verify profile parsing, both architectures, current Go tests, shell syntax,
  and FBD's existing ARM64 release tests.

### 2. Proxmox host adapter and new disposable VM

- Read the Proxmox host inventory before selecting a new VM ID, storage, bridge,
  or image. Never infer those values from VM 190.
- Produce a reviewable provisioning plan from the committed Proxmox profile.
- Create a new Ubuntu 24.04 AMD64 VM with separate replaceable system and
  retained data disks, QEMU guest agent, private development SSH management,
  and no inherited service identity.
- Bootstrap only the pinned container runtime. Do not deploy Device Sync,
  Shared Spaces, Tor identities, Principal state, or Persona state in this gate.

### 3. Common service-appliance installation

- Build an AMD64 service kit from an exact committed FacetsNode revision and
  source tree using the same recipes and acceptance record as FBD.
- Install into the new VM without exposing the container socket to workloads.
- Prove image digest/platform binding, rendered Compose boundaries, private
  management, dedicated persistent volumes, and clean restart.
- Generate fresh disposable Box/service authorities only during an explicit
  attended activation checkpoint.

### 4. FBD convergence

- Make FBD consume the same versioned appliance profile and service-release
  semantics while retaining Virtualization.framework, virtio management, ARM64
  foundation signing, macOS lifecycle, and rollback checks.
- Alternate routine service development on the faster host while running signed
  FBD acceptance at release checkpoints. Passing one adapter does not establish
  runtime acceptance on the other.

### 5. Carriage, identity, Sync, and Shared Spaces integration

- Integrate the reviewed Carriage envelope/key contract as the common E2EE
  transport/custody layer. Carriage implements content confidentiality and
  integrity; service-level admission, roster, quota, and authorization remain
  higher-layer responsibilities.
- Replace any remaining nearby/ad-hoc Sync path with the sole Box-mediated Sync
  service path. Connection policy may support direct access, Tor discovery with
  an authenticated direct route, or Tor for all traffic; route changes must be
  explicit and authenticated.
- Bind Sync participation to the Box account derived from the Principal rather
  than exposing a second user-facing Sync Group concept, subject to the identity
  contract review. Shared Spaces presents a selected Persona in its participant
  and roster surfaces.
- Define encrypted cross-device bootstrap and recovery for the private account
  and Persona library without making the Box a plaintext identity directory.

## Evidence gates

Each checkpoint reports these separately: source implementation, local build,
unit/integration tests, signed artifact verification, installed-VM runtime,
client functional acceptance, recovery/relocation acceptance, and deployment
readiness. Historical acceptance records remain evidence, not current proof.

The immediate implementation scope includes checkpoint 3's dormant service-kit
installation and restart proof. Service activation and durable identity creation
remain a separate attended checkpoint after the active Facets work supplies
stable integration contracts.
