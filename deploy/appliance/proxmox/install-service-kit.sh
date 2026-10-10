#!/bin/bash
# Install and accept a service kit in a prepared Proxmox appliance VM. This
# deliberately creates no durable Box, service, Tor, Principal, or Persona identity.
set -euo pipefail
trap 'printf "Service-kit installation stopped at line %s (status %s).\n" "$LINENO" "$?" >&2' ERR

if [[ $# != 2 || $1 != install ]]; then
  printf 'Usage: %s install BUNDLE_DIRECTORY\n' "$0" >&2
  exit 64
fi
[[ $(id -u) == 0 ]] || { printf 'Service-kit installation must run as root.\n' >&2; exit 1; }
bundle=$(cd "$2" && pwd)
for name in SHA256SUMS facets-service-kit install-service-kit.sh source.tar source.tar.json; do
  [[ -f $bundle/$name && ! -L $bundle/$name ]] || exit 1
done
(cd "$bundle" && sha256sum --check --strict SHA256SUMS)

install_exact() {
  local source=$1 target=$2 mode=$3
  if [[ -e $target ]]; then
    [[ -f $target && ! -L $target ]] || exit 1
    cmp --silent "$source" "$target" || {
      printf 'Refusing to replace a different installed artifact: %s\n' "$target" >&2
      exit 1
    }
    return
  fi
  install -m "$mode" "$source" "$target"
}

install -d -m 0755 /usr/local/libexec
install -d -m 0700 /srv/facets-box-data/staging
install_exact "$bundle/facets-service-kit" /usr/local/libexec/facets-service-kit 0755
install_exact "$bundle/source.tar" /srv/facets-box-data/staging/source.tar 0600
install_exact "$bundle/source.tar.json" /srv/facets-box-data/staging/source.tar.json 0600
exec /usr/local/libexec/facets-service-kit portable-service-kit install
