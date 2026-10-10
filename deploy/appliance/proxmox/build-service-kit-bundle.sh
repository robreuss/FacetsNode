#!/bin/bash
# Produce a reviewable AMD64 service-kit input bundle from exactly origin/main.
# The archive and installer binary come from that same committed source tree.
set -euo pipefail
trap 'printf "Service-kit bundle build stopped at line %s (status %s).\n" "$LINENO" "$?" >&2' ERR

if [[ $# != 2 ]]; then
  printf 'Usage: %s COMMITTED_REVISION NEW_OUTPUT_DIRECTORY\n' "$0" >&2
  exit 64
fi
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
revision=$(git -C "$repo" rev-parse --verify --end-of-options "$1^{commit}")
tree=$(git -C "$repo" rev-parse "$revision^{tree}")
[[ $revision == "$(git -C "$repo" rev-parse HEAD)" && $revision == "$(git -C "$repo" rev-parse origin/main)" ]] || {
  printf 'Revision must be the checked-out, pushed origin/main commit.\n' >&2
  exit 1
}
[[ -z $(git -C "$repo" status --porcelain) ]] || {
  printf 'Source checkout must be clean.\n' >&2
  exit 1
}
output=$2
[[ ! -e $output ]] || { printf 'Output must not already exist.\n' >&2; exit 1; }
command -v go >/dev/null
command -v jq >/dev/null
mkdir -m 0700 -p "$output"
output=$(cd "$output" && pwd)
staging=$(mktemp -d -t facets-service-kit-source)
trap 'test -n "$staging" && test -d "$staging" && /bin/rm -r "$staging"' EXIT

git -C "$repo" archive --format=tar --output="$output/source.tar" "$revision"
tar -xf "$output/source.tar" -C "$staging"
(cd "$staging" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$output/facets-service-kit" ./deploy/desktop/guest)
cp "$staging/deploy/appliance/proxmox/install-service-kit.sh" "$output/install-service-kit.sh"
chmod 0600 "$output/source.tar"
chmod 0700 "$output/facets-service-kit" "$output/install-service-kit.sh"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}
source_hash=$(hash_file "$output/source.tar")
source_size=$(wc -c < "$output/source.tar" | tr -d ' ')
jq -n --arg kind source --arg sha256 "$source_hash" --arg revision "$revision" --arg tree "$tree" --argjson size "$source_size" \
  '{kind:$kind,size:$size,sha256:$sha256,revision:$revision,tree:$tree}' > "$output/source.tar.json"
chmod 0600 "$output/source.tar.json"

(
  cd "$output"
  for name in facets-service-kit install-service-kit.sh source.tar source.tar.json; do
    printf '%s  %s\n' "$(hash_file "$name")" "$name"
  done > SHA256SUMS
)
chmod 0600 "$output/SHA256SUMS"
printf 'Prepared AMD64 service-kit bundle from revision=%s tree=%s. Activation is not included.\n' "$revision" "$tree"
