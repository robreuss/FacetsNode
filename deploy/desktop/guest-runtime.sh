#!/bin/bash
# Private signed developer recipe; never accepts caller-supplied commands.
set -euo pipefail
[[ ${1:-} == prepare ]] || exit 64
/opt/fbd/guest-agent check-storage
IFS=$'\t' read -r profile_id architecture host_adapter engine_version compose_version containerd_version data_root profile_sha256 < <(/opt/fbd/guest-agent appliance-profile)
case $architecture in arm64|amd64) ;; *) exit 1;; esac
[[ $(dpkg --print-architecture) == "$architecture" && $profile_id == facets-box-desktop-arm64 && $host_adapter == fbd-virtualization-framework && $profile_sha256 =~ ^[0-9a-f]{64}$ ]] || exit 1
export DEBIAN_FRONTEND=noninteractive
runtime_root=/srv/facets-box-data/runtime
if [[ -d /opt/fbd/runtime-kit ]]; then runtime_root=/opt/fbd/runtime-kit; fi
install -d -m 0700 "$runtime_root/debs" /etc/docker /etc/containerd
# Package postinst hooks cannot launch an unconfigured daemon.
systemctl mask --runtime docker.service docker.socket containerd.service
trap 'systemctl unmask --runtime docker.service docker.socket containerd.service' EXIT
# A kit produced on the same immutable Ubuntu base supplies dependencies too.
# Offline restore fails closed if its dependency closure is incomplete.
if [[ -f "$runtime_root/SHA256SUMS" ]]; then
  (cd "$runtime_root" && sha256sum --check SHA256SUMS)
  # apt --no-download mishandles local .deb paths on Noble. dpkg never accesses
  # a repository: unpack the complete set, then configure in dependency order.
  dpkg --unpack "$runtime_root"/debs/*.deb
  dpkg --configure -a
else
cat > /etc/apt/apt.conf.d/99fbd-cache <<'APT'
Binary::apt::APT::Keep-Downloaded-Packages "true";
APT::Keep-Downloaded-Packages "true";
APT::Install-Recommends "false";
APT
apt-get update
apt-get install -y ca-certificates curl gnupg
install -d -m 0755 /etc/apt/keyrings
curl --fail --location --retry 3 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc | grep -q '^fpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:'
chmod 0644 /etc/apt/keyrings/docker.asc
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable\n' "$architecture" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y \
 "docker-ce=5:${engine_version}-1~ubuntu.24.04~noble" \
 "docker-ce-cli=5:${engine_version}-1~ubuntu.24.04~noble" \
 "containerd.io=${containerd_version}-1~ubuntu.24.04~noble" \
 'docker-buildx-plugin=0.31.1-1~ubuntu.24.04~noble' \
 "docker-compose-plugin=${compose_version}-1~ubuntu.24.04~noble" skopeo jq
apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
cp /var/cache/apt/archives/*.deb "$runtime_root/debs/"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > "$runtime_root/packages.tsv"
(cd "$runtime_root" && sha256sum debs/*.deb > SHA256SUMS)
fi
apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
printf '{"data-root":"%s","live-restore":false,"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}\n' "$data_root" > /etc/docker/daemon.json
cat > /etc/containerd/config.toml <<'TOML'
version = 3
root = "/srv/facets-box-data/containerd"
state = "/run/containerd"
TOML
systemctl unmask --runtime docker.service docker.socket containerd.service
trap - EXIT
systemctl daemon-reload
systemd-analyze --man=no verify fbd-data.service fbd-guest.service docker.service docker.socket containerd.service
systemctl enable --now containerd.service docker.service
[[ $(docker info --format '{{.DockerRootDir}}') == "$data_root" ]]
[[ $(docker version --format '{{.Server.Version}}') == "$engine_version" ]]
[[ $(docker compose version --short) == "$compose_version" ]]
install -d -m 0700 /srv/facets-box-data/staging
tar -cf /srv/facets-box-data/staging/runtimeKit.tar.new -C "$runtime_root" debs SHA256SUMS packages.tsv
mv /srv/facets-box-data/staging/runtimeKit.tar.new /srv/facets-box-data/staging/runtimeKit.tar
jq -n --arg docker "$engine_version" --arg compose "$compose_version" --arg containerd "$containerd_version" --arg profileID "$profile_id" --arg profileSHA256 "$profile_sha256" \
  '{docker:$docker,compose:$compose,containerd:$containerd,durableRoots:"verified",applianceProfileID:$profileID,applianceProfileSHA256:$profileSHA256}' > /opt/fbd/runtime-ready.json
