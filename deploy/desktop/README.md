# Desktop appliance packaging

The initial foundation image is Ubuntu 24.04 minimal ARM64 with private virtio-socket management. It is not yet the service-bearing Box appliance. The manifest has an empty service image map, so the host must never describe it as service-ready.

`build-foundation.sh` exports an explicitly selected committed revision, cross-builds the private guest agent, verifies the pinned upstream image checksum, converts it to a 16 GiB raw system disk, and signs the result using `fbdctl`. Its build-only dependencies are Go, qemu-img, curl, and the host CLI; installation requires none of these. The script reads no uncommitted source. The seed ISO containing installation credentials is generated privately by the host, never distributed.

The data disk is a separate raw image with an ext4 filesystem whose UUID is the host's expected data identity. Only initial installation may format a blank disk; subsequent system images require the existing identity. Missing, mismatched, or unrecognized storage fails closed. A persistent installation marker and random sentinel establish cross-boot continuity. Named authenticated guest operations use AF_VSOCK port 4050 from host CID 2. There is no IP management listener, SSH account, arbitrary guest command/path interface, workload Docker socket exposure, or new Facets service.

## Stage 2 implementation in progress

`guest-runtime.sh` pins Docker Engine/CLI 29.8.0, containerd 2.3.5, Compose 5.5.1 and Buildx 0.31.1. Developer preparation uses authenticated official repositories and exports the complete downloaded dependency set with package versions and hashes. A prepared `runtimeKit.tar` can be passed to the artifact builder using `FBD_RUNTIME_KIT`. It is signed with the release, carried on the read-only seed and hash-verified before extraction. Offline installation uses dpkg unpack/configure, not repository access. Ordinary installation does not need Docker Desktop, Homebrew or Linux commands.

`fbd-data.service` mounts and checks the identified ext4 data disk; Docker, containerd and socket activation require that unit, and both daemons recheck identity before starting. Their durable roots are `/srv/facets-box-data/docker` and `/srv/facets-box-data/containerd`. The guest health channel remains available when storage initialization fails. No containers are automatically deployed by runtime preparation.

The host CLI exports an explicitly selected committed source archive. The guest verifies its authenticated hash, bounded size, contiguous chunks and safe archive entries, including Git's specific PAX commit metadata. A separate build operation uses the existing Dockerfile targets and Tor recipe. It has a 45-minute deadline, a 3-CPU/6-GiB builder, bounded private output, and does not install its result. OCI layout artifacts record their manifest digests separately from configuration IDs. The verifier binds the selected OCI index, manifest, architecture, configuration and layer hashes. Full service-kit build/runtime acceptance is still being completed.

Desktop overlays are new files, applied after the frozen base and onion profiles. They preserve the Box controller's private Spaces Sync connection, suppress discovery and inherited published ports, retain separate Group Spaces state/networks, and use explicit no-restart policies so appliance orchestration controls activation. Caddy's separate local management socket has only reviewed controller routes. These overlays are staged code, not yet runtime network-boundary proof.

Fresh appliance configuration generation creates independent credentials, deployment signing keys, TLS keys and pinned onion route policies, then publishes the complete configuration atomically. Existing inconsistent configuration is rejected rather than replaced. This code is tested but not yet connected to full Box initialization/claim.

## Integration boundary

Coordinated frozen service snapshot: `0d02383d818177f3443b79482c02beafefb1df31`, tree `03120d567412773791b3b4d2133c551b217a53e3`. The user authorized coordination with the Spaces Sync task on 2026-09-09. Its second ordinary-Space native acceptance passed and was recorded in Facets commit `fbbf0b18`, `docs/development/facets-vm-lab.md`; encrypted receiver-at-rest parity is not proven by that run. Leave its Proxmox instance and A/B participant state untouched. No base Compose, controller, shared-contract or client edits are required for independent packaging.

The native OCI exporter selects the exact inspected ARM64 manifest, preserving
its digest rather than comparing it with a configuration ID. A successful kit
publication additionally requires complete OCI hash verification, rendered
Compose isolation checks and Caddy configuration parsing in a network-disabled
validation container. These checks are explicitly distinct from service runtime
and Spaces Sync acceptance. Prepared Linux import, offline onion identity and
resumable controller-initialization functions are not yet wired into service boot.

`runtime-15` built and exported an accepted six-image kit including an actual
network-disabled Tor identity creation/restart test. SHA-256 of the exported kit:
`71cb77f4ac6d1513c1be00d55caf0d400de4283f9f9566fe2398537d0a4569b1`.
The test removed only its uniquely named disposable containers/volume. The
retained appliance disk UUID/sentinel survived another clean stop/cold boot.
Onion continuity records now bind both key files and the checksum-verified
hostname. Interrupted initialization containers are reconciled only after
matching their name, image and installation/operation ownership labels.

`runtime-19` passed the existing service recipes with disposable project names,
databases and identities, with Tor stopped and no published ports. It exercised
controller initialization/claim over verified HTTPS on its private Unix socket,
and container recreation with retained volumes, Box ID/key and claimed state.
The exported `serviceKit-4.tar` SHA-256 is
`57d0dd2eb410ade48f84515bdec6d30c06ded9b1fee5637ea25a1f8b6b639a78`.
The first attempts exposed Docker image-root naming collisions; verified imports
now use unique per-image references without changing signed OCI content digests.
This is isolated build acceptance, not an installed Box or client Sync proof.
The named `openManagement` stream
also requires a matching active release record and can only reach the fixed
controller-only Unix socket. No current foundation image creates that record.

Remaining Stage 2 gates: signed service release installation, installed Box
initialization/claim and private activation-code UI, controller-only pinned HTTPS
administration through the host, and installed-service health/persistence checks.
Before service-bearing updates are accepted, prove bounded candidate startup,
withheld ingress/background activity, and consistent database/system/data
rollback.

Spaces Sync confirmed its committed ordinary-Space/signed-update handoff
(`fbbf0b18`, `c8e42870` in Facets) permits the narrow default-off maintenance
integration. `FACETS_DEVICE_SYNC_CANDIDATE_MAINTENANCE` and
`FACETS_SHARED_SPACES_CANDIDATE_MAINTENANCE` fence application HTTP/stream
dispatch and prevent starting relay-wake, expiry and blob-maintenance workers.
Only exact GET/HEAD `/livez` and `/readyz` routes remain, with
`X-Facets-Serving-Mode: candidate`; a separate `candidate-healthcheck` command
requires that marker plus successful readiness. Startup schema migration and
durable authority recovery remain permitted. This is **not database read-only**,
and does not replace the appliance's ingress fence/consistent rollback disks.
Normal serving is unchanged unless the service-specific boolean is explicitly
enabled. New maintenance-bearing source/image evidence must be recorded separately
from the frozen `0d02383d` native acceptance; Proxmox remains untouched.

`runtime-20` exported `serviceKit-5.tar`, SHA-256
`65c7929e61d6e4cfdf1f428de94dc1bd546c1a4cc3f8136b5e5225c501872f93`,
from service source `40713ff96557f069f9cb7d780bc7ada60db06ce7`, tree
`cf1facb4128462822f0d1264bd74c861aa826a11`. Its isolated runtime acceptance
adds actual candidate readiness and GET/POST/stream rejection probes on both
servers, repeated candidate startup, then restart in normal mode retaining the
controller identity and claimed state. No Tor publication or client Sync was
performed. The earlier attempt failed because a source-archive test expected
checkout Git metadata; it now creates its own committed temporary repository,
including inside the existing Docker build. No tests were skipped to publish it.

Installed service orchestration is now staged behind the host's service-install
gate. It prepares verified images, records independently owned persistent
volumes, initializes the existing controller and starts the two deployments in
candidate mode before attended activation. Random volume identity labels prevent
missing/replaced Docker volumes from being silently substituted. Readiness
aggregates all deployments (one healthy database cannot mask another's failure),
and explicit shutdown stops Tor, applications/management, then databases.
These newly wired production functions still need a signed installed-appliance
runtime acceptance; the kit's disposable fixtures do not prove that path.

No Proxmox deployment or Spaces Sync task is accessed by these scripts.
