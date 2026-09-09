#!/bin/bash
# Called only with an appliance-created staging directory and authenticated
# commit/tree identifiers. This builds the existing recipes, never deploys them.
set -euo pipefail
trap 'printf "Service build stopped at recipe line %s (status %s).\n" "$LINENO" "$?" >&2' ERR
[[ $# == 3 && $1 == /srv/facets-box-data/staging/build-* && $2 =~ ^[0-9a-f]{40}$ && $3 =~ ^[0-9a-f]{40}$ ]] || exit 64
build_root=$1
revision=$2
tree=$3
/opt/fbd/guest-agent check-storage
[[ $(df --output=avail -B1 /srv/facets-box-data | tail -1) -gt 12884901888 ]]
kit="$build_root/kit"
install -d -m 0700 "$kit/images" "$kit/recipes"
cp "$build_root/source/compose.yaml" "$kit/recipes/device-sync.compose.yaml"
cp "$build_root/source/deploy/shared-spaces/compose.yaml" "$kit/recipes/shared-spaces.compose.yaml"
cp "$build_root/source/deploy/onion/device-sync.compose.yaml" "$kit/recipes/device-sync.onion.yaml"
cp "$build_root/source/deploy/onion/shared-spaces.compose.yaml" "$kit/recipes/shared-spaces.onion.yaml"
cp /opt/fbd/recipes/device-sync.compose.yaml "$kit/recipes/device-sync.desktop.yaml"
cp /opt/fbd/recipes/shared-spaces.compose.yaml "$kit/recipes/shared-spaces.desktop.yaml"
cp /opt/fbd/recipes/*.Caddyfile "$kit/recipes/"
# The builder is infrastructure, with a finite CPU/memory envelope. No ordinary
# Facets container is created here and no workload receives the Docker socket.
if ! docker buildx inspect fbd-builder >/dev/null 2>&1; then
  docker buildx create --name fbd-builder --driver docker-container --driver-opt memory=6g,cpu-period=100000,cpu-quota=300000 >/dev/null
fi
for target in device-sync box-controller shared-spaces; do
  docker buildx build --builder fbd-builder --platform linux/arm64 --load \
    --build-arg "FACETS_SERVER_SOURCE_REVISION=$revision" --build-arg "FACETS_SERVER_SOURCE_TREE=$tree" \
    --target "$target" --tag "fbd-build/$target:$revision" "$build_root/source"
done
docker buildx build --builder fbd-builder --platform linux/arm64 --load --tag "fbd-build/tor:$revision" "$build_root/source/deploy/onion"
docker pull --platform linux/arm64 postgres:17.6-bookworm
docker pull --platform linux/arm64 caddy:2.10.2-alpine
printf '{}' > "$kit/images.json"
for name in device-sync box-controller shared-spaces tor postgres caddy; do
  ref="fbd-build/$name:$revision"
  case $name in postgres) ref=postgres:17.6-bookworm;; caddy) ref=caddy:2.10.2-alpine;; esac
  [[ $(docker image inspect --format '{{.Architecture}}' "$ref") == arm64 ]]
  # Use the pinned Docker CLI for daemon operations. Skopeo handles portable
  # archives/layouts, so its bundled Docker API client version is irrelevant.
  docker image save --platform linux/arm64 --output "$build_root/export-$name.tar" "$ref"
  # Docker 29's containerd export includes OCI layout plus a legacy Docker
  # compatibility record. Reading it as docker-archive rewrites configuration
  # JSON; consume the native OCI layout and require digest preservation.
  skopeo inspect --raw "oci-archive:$build_root/export-$name.tar" > "$build_root/manifest-$name.json"
  exported_manifest="sha256:$(sha256sum "$build_root/manifest-$name.json" | cut -d ' ' -f 1)"
  skopeo copy --preserve-digests "oci-archive:$build_root/export-$name.tar" "oci:$kit/images/$name:release"
  digest=$(jq -r '.manifests[0].digest' "$kit/images/$name/index.json")
  config=$(jq -r '.config.digest' "$kit/images/$name/blobs/sha256/${digest#sha256:}")
  daemon_manifest=$(docker image inspect --platform linux/arm64 --format '{{.Id}}' "$ref")
  printf 'Verified export %s: daemon-manifest=%s exported-manifest=%s OCI-manifest=%s\n' "$name" "$daemon_manifest" "$exported_manifest" "$digest"
  [[ $digest == "$exported_manifest" && $digest == "$daemon_manifest" ]]
  jq --arg name "$name" --arg digest "$digest" --arg config "$config" --arg ref "$ref" '. + {($name):{digest:$digest,config:$config,reference:$ref}}' "$kit/images.json" > "$kit/images.json.new"
  mv "$kit/images.json.new" "$kit/images.json"
done
jq -n --arg revision "$revision" --arg tree "$tree" --slurpfile images "$kit/images.json" \
 '{version:1,architecture:"arm64",sourceRevision:$revision,sourceTree:$tree,images:$images[0],acceptance:{dockerfileTests:"passed",serviceRuntime:"not-run",spacesSync:"not-run"}}' > "$kit/service-release.json"
tar -cf /srv/facets-box-data/staging/serviceKit.tar.new -C "$kit" images recipes images.json service-release.json
mv /srv/facets-box-data/staging/serviceKit.tar.new /srv/facets-box-data/staging/serviceKit.tar
