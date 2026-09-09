# Desktop appliance packaging

The initial foundation image is Ubuntu 24.04 minimal ARM64 with private virtio-socket management. It is not yet the service-bearing Box appliance. The manifest has an empty service image map, so the host must never describe it as service-ready.

`build-foundation.sh` exports an explicitly selected committed revision, cross-builds the private guest agent, verifies the pinned upstream image checksum, converts it to a 16 GiB raw system disk, and signs the result using `fbdctl`. Its build-only dependencies are Go, qemu-img, curl, and the host CLI; installation requires none of these. The script reads no uncommitted source. The seed ISO containing installation credentials is generated privately by the host, never distributed.

The data disk is a separate raw image with an ext4 filesystem whose UUID is the host's expected data identity. Only initial installation may format a blank disk; subsequent system images require the existing identity. Missing, mismatched, or unrecognized storage fails closed. A persistent installation marker and random sentinel establish cross-boot continuity. Guest management accepts authenticated `status`, `shutdown`, and foundation-only `activate` operations on AF_VSOCK port 4050 from host CID 2. There is no IP management listener, SSH account, Docker socket exposure, or new Facets service.

## Integration boundary

Next packaging work must pin Docker Engine/Compose, persist both Docker and containerd roots on the data filesystem, and deploy the existing device-sync/controller and separate Group Spaces recipes. It must not edit the existing Compose bases, controller, shared contracts, or client code before the authorized handoff. Tor, pinned HTTPS controller tunneling, Box claim, service readiness, guest builds of service candidates, and actual service-data update acceptance are not implemented by this foundation image.

No Proxmox deployment or Spaces Sync task is accessed by these scripts.
