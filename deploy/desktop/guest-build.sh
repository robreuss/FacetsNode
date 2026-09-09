#!/bin/bash
# Called only with an appliance-created staging directory and authenticated
# commit/tree identifiers. This builds the existing recipes, never deploys them.
set -euo pipefail
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
  skopeo copy "docker-daemon:$ref" "oci:$kit/images/$name:release"
  digest=$(jq -r '.manifests[0].digest' "$kit/images/$name/index.json")
  config=$(jq -r '.config.digest' "$kit/images/$name/blobs/sha256/${digest#sha256:}")
  [[ $config == "$(docker image inspect --format '{{.Id}}' "$ref")" ]]
  jq --arg name "$name" --arg digest "$digest" --arg config "$config" --arg ref "$ref" '. + {($name):{digest:$digest,config:$config,reference:$ref}}' "$kit/images.json" > "$kit/images.json.new"
  mv "$kit/images.json.new" "$kit/images.json"
done
jq -n --arg revision "$revision" --arg tree "$tree" --slurpfile images "$kit/images.json" \
 '{version:1,architecture:"arm64",sourceRevision:$revision,sourceTree:$tree,images:$images[0],acceptance:{dockerfileTests:"passed",serviceRuntime:"not-run",spacesSync:"not-run"}}' > "$kit/service-release.json"
tar -cf /srv/facets-box-data/staging/serviceKit.tar.new -C "$kit" .
mv /srv/facets-box-data/staging/serviceKit.tar.new /srv/facets-box-data/staging/serviceKit.tar
