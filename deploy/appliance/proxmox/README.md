# Proxmox development host adapter

This adapter creates a fresh Ubuntu 24.04 AMD64 VM for the portable Facets Box
profile. It does not clone an existing VM, copy a Box identity, activate a
service, or mutate retained VMs 180 and 190.

The workflow has two independently reviewed changes:

1. `facets-proxmox-vm` creates a VM with separate replaceable system and
   authority-retaining data disks. It requires exact cloud-image and SSH-key
   hashes and an approval digest over the complete plan.
2. `bootstrap-runtime.sh` runs inside that fresh VM. It formats only an explicit
   blank `/dev/disk/by-id/...` disk after checking that it is not mounted, has no
   filesystem signature, and does not back `/`. It installs the pinned container
   runtime with all mutable runtime data on `/srv/facets-box-data`.

Neither step deploys Device Sync, Shared Spaces, Box Controller, Tor, Carriage,
Principal, Persona, or Worker state.

The preferred development path uses the dedicated Proxmox API automation token
from the operator workstation. It pins the PVE leaf-certificate SHA-256, keeps
the token secret out of plans and command-line arguments, uploads a checksum-
bound cloud image, and refuses to run during a PVE backup or excessive host
load. The root-local `qm` path remains available for an attended host-console
workflow, but is not required for normal provisioning.

## API-token workflow

Create a private local staging directory and fetch the pinned image. The fetch
script works on Linux and macOS and refuses to overwrite an existing artifact:

```sh
install -d -m 0700 /private/staging/directory
./fetch-cloud-image.sh /private/staging/directory
```

Create an API plan from live inventory. The VM ID, node, storages, bridge, API
origin, certificate digest, and public key are review inputs; none is inferred
from an existing Box VM. `api-plan` refuses retained VM IDs 180 and 190 and
binds the exact source image and SSH public-key hashes:

```sh
facets-proxmox-vm api-plan \
  --profile deploy/appliance/proxmox-development-amd64.json \
  --output /private/staging/directory/facets-box-api-plan.json \
  --endpoint https://PVE_HOST:8006 \
  --tls-cert-sha256 LOWERCASE_LEAF_CERT_SHA256 \
  --node PVE_NODE --vmid UNUSED_ID --name facets-box-portable-dev \
  --storage PVE_IMAGE_STORAGE --image-storage PVE_ISO_STORAGE \
  --bridge PVE_BRIDGE --admin-user facets-admin \
  --cloud-image /private/staging/directory/ubuntu-24.04-minimal-cloudimg-amd64-20260905.img \
  --ssh-public-key /private/key/location/facets-infrastructure-ed25519.pub

facets-proxmox-vm api-review \
  --profile deploy/appliance/proxmox-development-amd64.json \
  --plan /private/staging/directory/facets-box-api-plan.json
```

Load the token secret from a protected credential store into the process
environment, run the read-only preflight, then apply the exact approval digest
printed by `api-plan`:

```sh
export FACETS_PROXMOX_API_TOKEN_ID='USER@REALM!TOKEN'
export FACETS_PROXMOX_API_TOKEN_SECRET='FROM_PROTECTED_CREDENTIAL_STORE'
facets-proxmox-vm api-check \
  --profile deploy/appliance/proxmox-development-amd64.json \
  --plan /private/staging/directory/facets-box-api-plan.json
facets-proxmox-vm api-apply \
  --profile deploy/appliance/proxmox-development-amd64.json \
  --plan /private/staging/directory/facets-box-api-plan.json \
  --approval EXACT_PLAN_SHA256
unset FACETS_PROXMOX_API_TOKEN_SECRET
```

The apply path uploads the image, creates and configures the VM, and starts it.
If any operation fails, it reports the failed gate and leaves the uploaded image
or partial VM in place for explicit review; it never deletes infrastructure.

## Root-local host workflow

### Build the host tools

From the committed FacetsNode checkout:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -trimpath -buildvcs=false -o facets-proxmox-vm \
  ./cmd/facets-proxmox-vm
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -trimpath -buildvcs=false -o facets-appliance-profile \
  ./cmd/facets-appliance-profile
```

Copy those binaries, `proxmox-development-amd64.json`, the two adapter scripts,
and one dedicated Ed25519 public key to a protected staging directory on the
PVE node. Do not use a private key as `--ssh-public-key`. Fetch the pinned
Ubuntu image into that directory with:

```sh
./fetch-cloud-image.sh /protected
```

The script pins the official 2026-09-05 Ubuntu 24.04 minimal AMD64 image by its
published SHA-256 and refuses to replace an existing file.

### Inventory and plan on the PVE node

All inventory values are live inputs, not repository defaults:

```sh
sudo ./facets-proxmox-vm next-id
pvesh get /nodes --output-format json-pretty
pvesm status --enabled 1
ip -brief link
```

Create the plan using the returned unused VM ID and reviewed node, storage, and
bridge. `plan` refuses to overwrite an existing file and prints its approval
SHA-256:

```sh
sudo ./facets-proxmox-vm plan \
  --profile /protected/proxmox-development-amd64.json \
  --output /protected/facets-box-vm-plan.json \
  --node PVE_NODE --vmid UNUSED_ID --name facets-box-portable-dev \
  --storage PVE_STORAGE --bridge PVE_BRIDGE --admin-user facets-admin \
  --cloud-image /protected/ubuntu-24.04-amd64.img \
  --ssh-public-key /protected/facets-box-admin.pub

sudo ./facets-proxmox-vm review \
  --profile /protected/proxmox-development-amd64.json \
  --plan /protected/facets-box-vm-plan.json
```

Review the plan and generated `qm` argument arrays. Apply only the exact printed
digest. The adapter repeats the inventory, architecture, bridge, capacity, and
file-hash checks immediately before the first mutation. It leaves any partial VM
in place for explicit diagnosis; it never destroys a VM automatically.

```sh
sudo ./facets-proxmox-vm apply \
  --profile /protected/proxmox-development-amd64.json \
  --plan /protected/facets-box-vm-plan.json \
  --approval EXACT_PLAN_SHA256
```

## Prepare the blank retained-data disk

After cloud-init finishes, connect as the non-root `facets-admin` account. Copy
the profile validator, profile, and bootstrap script into the new VM. Resolve
the new 64 GiB data disk by its stable `/dev/disk/by-id` name containing the
planned `facets-data` serial and inspect it with `lsblk`, then run:

```sh
sudo install -m 0755 facets-appliance-profile /usr/local/libexec/facets-appliance-profile
sudo ./bootstrap-runtime.sh prepare \
  /path/to/proxmox-development-amd64.json \
  /dev/disk/by-id/REVIEWED-BLANK-DATA-DISK \
  initialize-empty-data-disk
```

Record the resulting installation ID, data-filesystem UUID, exact FacetsNode
revision, profile digest, cloud-image digest, plan digest, and VM ID. At this
gate the correct runtime state is Docker healthy with no Facets workloads or
service identities installed.
