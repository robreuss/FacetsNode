#!/bin/bash
# Fetch the same pinned Ubuntu Noble minimal release family used by the FBD
# foundation builder, selecting the Proxmox host's AMD64 artifact.
set -euo pipefail
umask 077
if [[ $# != 1 || ! -d $1 ]]; then
  printf 'Usage: %s EXISTING_PROTECTED_DIRECTORY\n' "$0" >&2
  exit 64
fi
output_directory=$(cd "$1" && pwd)
output="$output_directory/ubuntu-24.04-minimal-cloudimg-amd64-20260905.img"
[[ ! -e $output && ! -e $output.download ]] || { printf 'Cloud image output already exists.\n' >&2; exit 1; }
url=https://cloud-images.ubuntu.com/minimal/releases/noble/release-20260905/ubuntu-24.04-minimal-cloudimg-amd64.img
expected=46b0dbaffa6950a7da5ff2dc5ed34c46084610b3b6d1fae8f1ec2d7e953984a3
curl --fail --location --retry 3 "$url" -o "$output.download"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$output.download" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$output.download" | cut -d ' ' -f 1)
fi
[[ $actual == "$expected" ]] || { printf 'Ubuntu cloud image checksum mismatch.\n' >&2; exit 1; }
chmod 0600 "$output.download"
mv "$output.download" "$output"
printf '%s  %s\n' "$actual" "$output"
