#!/usr/bin/env bash
set -euo pipefail

lab_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

ROOT=$(lab_root)
IMAGE_DIR="$ROOT/kvm/images"
DEFAULT_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
DEFAULT_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
URL=${UBUNTU_CLOUD_IMAGE_URL:-$DEFAULT_URL}
OUT=${UBUNTU_CLOUD_IMAGE:-$IMAGE_DIR/$DEFAULT_NAME}
SHA256_URL=${UBUNTU_CLOUD_IMAGE_SHA256_URL:-https://cloud-images.ubuntu.com/noble/current/SHA256SUMS}
VERIFY=${VERIFY_SHA256:-1}
FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL=$2; shift 2 ;;
    --output) OUT=$2; shift 2 ;;
    --sha256-url) SHA256_URL=$2; shift 2 ;;
    --no-verify) VERIFY=0; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help)
      cat <<USAGE
usage: $0 [--url URL] [--output PATH] [--sha256-url URL] [--no-verify] [--force]

Downloads the Ubuntu 24.04 amd64 cloud image to the Phase 6 lab image path.
Default output:
  test-lab/kvm/images/$DEFAULT_NAME

Environment overrides:
  UBUNTU_CLOUD_IMAGE_URL
  UBUNTU_CLOUD_IMAGE
  UBUNTU_CLOUD_IMAGE_SHA256_URL
  VERIFY_SHA256=0
USAGE
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

require_cmd curl
require_cmd qemu-img
if [ "$VERIFY" = 1 ]; then
  require_cmd sha256sum
fi

mkdir -p "$(dirname "$OUT")"
if [ -f "$OUT" ] && [ "$FORCE" != 1 ]; then
  echo "image already exists: $OUT"
  qemu-img info "$OUT"
  exit 0
fi

TMP="$OUT.tmp.$$"
trap 'rm -f "$TMP" "$TMP.sha256"' EXIT

echo "Downloading Ubuntu cloud image"
echo "  from: $URL"
echo "  to:   $OUT"
curl -fL --retry 3 --retry-delay 2 -o "$TMP" "$URL"

if [ "$VERIFY" = 1 ]; then
  echo "Downloading SHA256SUMS: $SHA256_URL"
  curl -fL --retry 3 --retry-delay 2 -o "$TMP.sha256" "$SHA256_URL"
  expected=$(awk -v name="$(basename "$URL")" '$2 == "*" name || $2 == name { print $1; exit }' "$TMP.sha256")
  if [ -z "$expected" ]; then
    expected=$(awk -v name="$(basename "$OUT")" '$2 == "*" name || $2 == name { print $1; exit }' "$TMP.sha256")
  fi
  if [ -z "$expected" ]; then
    echo "could not find checksum entry for $(basename "$URL") in SHA256SUMS" >&2
    exit 1
  fi
  actual=$(sha256sum "$TMP" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
  echo "checksum verified: $actual"
fi

mv "$TMP" "$OUT"
qemu-img info "$OUT"
echo "Image ready: $OUT"
