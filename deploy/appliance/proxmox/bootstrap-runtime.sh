#!/bin/bash
# Run only inside a newly created, identity-free appliance VM. This script
# initializes one explicitly named blank data disk and installs the pinned
# container runtime. It does not install or activate any Facets service.
set -euo pipefail
trap 'printf "Facets Box runtime bootstrap stopped at line %s (status %s).\n" "$LINENO" "$?" >&2' ERR

if [[ $# != 4 || $1 != prepare || $4 != initialize-empty-data-disk ]]; then
  printf 'Usage: %s prepare PROFILE.json /dev/disk/by-id/DATA-DISK initialize-empty-data-disk\n' "$0" >&2
  exit 64
fi
[[ $(id -u) == 0 ]] || { printf 'Runtime bootstrap must run as root.\n' >&2; exit 1; }

profile=$2
device_link=$3
validator=${FACETS_APPLIANCE_PROFILE_VALIDATOR:-/usr/local/libexec/facets-appliance-profile}
[[ -x $validator && -f $profile && $device_link == /dev/disk/by-id/*facets-data* ]] || exit 1
read -r profile_id architecture adapter < <("$validator" validate "$profile")
[[ $profile_id == facets-box-proxmox-development-amd64 && $architecture == amd64 && $adapter == proxmox-qemu ]] || exit 1
[[ $(dpkg --print-architecture) == amd64 ]] || exit 1
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || exit 1

IFS=$'\t' read -r data_minimum_gib engine_version compose_version containerd_version data_root < <(
  /usr/bin/python3 - "$profile" <<'PY'
import json, sys
with open(sys.argv[1], "rb") as source:
    value = json.load(source)
fields = (
    value["storage"]["data"]["minimumGiB"],
    value["runtime"]["engineVersion"],
    value["runtime"]["composeVersion"],
    value["runtime"]["containerdVersion"],
    value["runtime"]["dataRoot"],
)
print(*fields, sep="\t")
PY
)
[[ $data_minimum_gib =~ ^[0-9]+$ && $data_root == /srv/facets-box-data/docker ]] || exit 1

device=$(readlink -f -- "$device_link")
[[ -b $device && $(lsblk -dn -o TYPE "$device") == disk ]] || exit 1
root_source=$(findmnt -n -o SOURCE /)
if lsblk -s -n -o PATH "$root_source" | grep -Fqx "$device"; then
  printf 'Refusing to initialize a disk that backs the root filesystem.\n' >&2
  exit 1
fi
if [[ -n $(lsblk -nr -o MOUNTPOINTS "$device" | sed '/^$/d') ]]; then
  printf 'Refusing to initialize a mounted data disk.\n' >&2
  exit 1
fi
if [[ -n $(wipefs --no-act --noheadings --output TYPE "$device") ]]; then
  printf 'Refusing to initialize a data disk with an existing signature.\n' >&2
  exit 1
fi
minimum_bytes=$((data_minimum_gib * 1024 * 1024 * 1024))
[[ $(blockdev --getsize64 "$device") -ge $minimum_bytes ]] || { printf 'Data disk is smaller than its appliance profile.\n' >&2; exit 1; }
[[ ! -e /srv/facets-box-data/installation-id ]] || { printf 'Appliance data already initialized.\n' >&2; exit 1; }
if grep -Fq '/srv/facets-box-data' /etc/fstab; then
  printf 'An appliance data mount already exists in fstab.\n' >&2
  exit 1
fi

mkfs.ext4 -q -L facets-box-data "$device"
data_uuid=$(blkid -s UUID -o value "$device")
[[ $data_uuid =~ ^[0-9a-f-]{36}$ ]] || exit 1
install -d -m 0700 /srv/facets-box-data
printf 'UUID=%s /srv/facets-box-data ext4 defaults,nodev,nosuid 0 2\n' "$data_uuid" >> /etc/fstab
mount /srv/facets-box-data
[[ $(findmnt -n -o UUID /srv/facets-box-data) == "$data_uuid" ]] || exit 1

export DEBIAN_FRONTEND=noninteractive
install -d -m 0700 /srv/facets-box-data/runtime/debs
install -d -m 0755 /etc/apt/keyrings /etc/docker /etc/containerd /etc/facets-box
systemctl mask --runtime docker.service docker.socket containerd.service
trap 'systemctl unmask --runtime docker.service docker.socket containerd.service >/dev/null 2>&1 || true' EXIT
apt-get update
apt-get install -y ca-certificates curl gnupg qemu-guest-agent
curl --fail --location --retry 3 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc | grep -q '^fpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:'
chmod 0644 /etc/apt/keyrings/docker.asc
printf '%s\n' 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable' > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y \
  "docker-ce=5:${engine_version}-1~ubuntu.24.04~noble" \
  "docker-ce-cli=5:${engine_version}-1~ubuntu.24.04~noble" \
  "containerd.io=${containerd_version}-1~ubuntu.24.04~noble" \
  'docker-buildx-plugin=0.31.1-1~ubuntu.24.04~noble' \
  "docker-compose-plugin=${compose_version}-1~ubuntu.24.04~noble" skopeo jq
apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
cp /var/cache/apt/archives/*.deb /srv/facets-box-data/runtime/debs/
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > /srv/facets-box-data/runtime/packages.tsv
(cd /srv/facets-box-data/runtime && sha256sum debs/*.deb > SHA256SUMS)

printf '%s\n' '{"data-root":"/srv/facets-box-data/docker","live-restore":false,"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}' > /etc/docker/daemon.json
cat > /etc/containerd/config.toml <<'TOML'
version = 3
root = "/srv/facets-box-data/containerd"
state = "/run/containerd"
TOML
systemctl unmask --runtime docker.service docker.socket containerd.service
trap - EXIT
systemctl daemon-reload
systemctl enable --now qemu-guest-agent.service containerd.service docker.service
[[ $(docker info --format '{{.DockerRootDir}}') == "$data_root" ]]
[[ $(docker version --format '{{.Server.Version}}') == "$engine_version" ]]
[[ $(docker compose version --short) == "$compose_version" ]]

installation_id=$(cat /proc/sys/kernel/random/uuid)
install -d -m 0700 /srv/facets-box-data/appliance
printf '%s' "$installation_id" > /srv/facets-box-data/installation-id
chmod 0600 /srv/facets-box-data/installation-id
install -m 0600 "$profile" /srv/facets-box-data/appliance/profile.json
install -m 0644 "$profile" /etc/facets-box/profile.json
printf 'Facets Box runtime prepared. installation=%s data=%s profile=%s\n' "$installation_id" "$data_uuid" "$profile_id"
