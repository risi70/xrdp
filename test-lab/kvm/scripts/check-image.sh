#!/usr/bin/env bash
set -euo pipefail

lab_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    return 1
  }
}
ROOT=$(lab_root)
status=0
image=${UBUNTU_CLOUD_IMAGE:-$ROOT/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img}
echo "Ubuntu cloud image: $image"
if [ ! -f "$image" ]; then
  echo "missing Ubuntu 24.04 cloud image" >&2
  echo "Place it at test-lab/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img or set UBUNTU_CLOUD_IMAGE." >&2
  exit 1
fi
if require_cmd qemu-img; then
  qemu-img info "$image"
else
  status=1
fi
exit "$status"
