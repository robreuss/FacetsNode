#!/bin/bash
# Private signed developer recipe; never accepts caller-supplied commands.
set -euo pipefail
[[ ${1:-} == prepare ]] || exit 64
/opt/fbd/guest-agent check-storage
[[ $(dpkg --print-architecture) == arm64 ]] || exit 1
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
printf '%s\n' 'deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable' > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y \
 'docker-ce=5:29.8.0-1~ubuntu.24.04~noble' \
 'docker-ce-cli=5:29.8.0-1~ubuntu.24.04~noble' \
 'containerd.io=2.3.5-1~ubuntu.24.04~noble' \
 'docker-buildx-plugin=0.31.1-1~ubuntu.24.04~noble' \
 'docker-compose-plugin=5.5.1-1~ubuntu.24.04~noble' skopeo jq
apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
cp /var/cache/apt/archives/*.deb "$runtime_root/debs/"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > "$runtime_root/packages.tsv"
(cd "$runtime_root" && sha256sum debs/*.deb > SHA256SUMS)
fi
apt-mark hold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
cat > /etc/docker/daemon.json <<'JSON'
{"data-root":"/srv/facets-box-data/docker","live-restore":false,"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}
JSON
cat > /etc/containerd/config.toml <<'TOML'
version = 3
root = "/srv/facets-box-data/containerd"
state = "/run/containerd"
TOML
systemctl unmask --runtime docker.service docker.socket containerd.service
trap - EXIT
systemctl daemon-reload
systemctl enable --now containerd.service docker.service
[[ $(docker info --format '{{.DockerRootDir}}') == /srv/facets-box-data/docker ]]
[[ $(docker version --format '{{.Server.Version}}') == 29.8.0 ]]
[[ $(docker compose version --short) == 5.5.1 ]]
install -d -m 0700 /srv/facets-box-data/staging
tar -cf /srv/facets-box-data/staging/runtimeKit.tar.new -C "$runtime_root" debs SHA256SUMS packages.tsv
mv /srv/facets-box-data/staging/runtimeKit.tar.new /srv/facets-box-data/staging/runtimeKit.tar
cat > /opt/fbd/runtime-ready.json <<'JSON'
{"docker":"29.8.0","compose":"5.5.1","containerd":"2.3.5","durableRoots":"verified"}
JSON
