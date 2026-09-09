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

Remaining Stage 2 gates: complete a service-kit build, signed service release assembly/installation, first Box initialization and private activation-code handling, controller-only pinned HTTPS administration, and existing-service health/persistence checks. Before service-bearing updates are accepted, prove bounded candidate startup, withheld ingress/background activity, and consistent database/system/data rollback. The existing cleanup timers have no initial tick; a longer cleanup period is only a bounded-lifetime constraint, not a general read-only service mode.

No Proxmox deployment or Spaces Sync task is accessed by these scripts.
