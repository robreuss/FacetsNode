#!/bin/bash
# Developer-only artifact producer. The installed app never requires these tools.
set -euo pipefail
if [[ $# != 5 ]]; then
  echo "Usage: $0 COMMITTED_REVISION NEW_OUTPUT_DIRECTORY FBDCTL PRIVATE_KEY RELEASE_ID" >&2
  exit 64
fi
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
revision=$(git -C "$repo" rev-parse --verify --end-of-options "$1^{commit}")
tree=$(git -C "$repo" rev-parse "$revision^{tree}")
output=$2
fbdctl=$3
key=$4
release=$5
[[ ! -e "$output" ]] || { echo "Output must not already exist." >&2; exit 1; }
command -v go >/dev/null
command -v qemu-img >/dev/null
mkdir -m 700 -p "$output"
output=$(cd "$output" && pwd)
staging=$(mktemp -d -t facets-box-source)
trap 'test -n "$staging" && test -d "$staging" && /bin/rm -r "$staging"' EXIT
git -C "$repo" archive --format=tar "$revision" | tar -xf - -C "$staging"
base_url=https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260905/ubuntu-24.04-minimal-cloudimg-arm64.img
base_hash=8b6e0e145ae2ce681d959b2b3aabcf724b027cbffff9ec8ba4d7dc789a3e6a98
cache=${FBD_BUILD_CACHE:-"${TMPDIR:-/tmp}/facets-box-image-cache"}
mkdir -m 700 -p "$cache"
base="$cache/ubuntu-noble-20260905-arm64.qcow2"
if [[ ! -f "$base" ]]; then
  curl --fail --location --retry 3 "$base_url" -o "$base.download"
  mv "$base.download" "$base"
fi
actual=$(shasum -a 256 "$base" | cut -d ' ' -f 1)
[[ "$actual" == "$base_hash" ]] || { echo "Ubuntu base checksum mismatch." >&2; exit 1; }
qemu-img convert -f qcow2 -O raw "$base" "$output/system.raw"
qemu-img resize -f raw "$output/system.raw" 16G
(cd "$staging" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$output/guest-agent" ./deploy/desktop/guest)
cp "$staging/deploy/desktop/guest-bootstrap.sh" "$output/guest-bootstrap.sh"
if [[ -f "$staging/deploy/desktop/guest-runtime.sh" ]]; then
  cp "$staging/deploy/desktop/guest-runtime.sh" "$output/guest-runtime.sh"
  chmod 600 "$output/guest-runtime.sh"
fi
chmod 600 "$output/system.raw" "$output/guest-agent" "$output/guest-bootstrap.sh"
"$fbdctl" sign "$output" "$key" "$release" "$revision" "$tree"
echo "Foundation release prepared from $revision. No Facets workload containers are included."
