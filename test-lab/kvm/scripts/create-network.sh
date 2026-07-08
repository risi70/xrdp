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
require_cmd virsh
NET_XML="$ROOT/kvm/libvirt/networks/xrdp-baf-lab.xml"
if virsh net-info xrdp-baf-lab >/dev/null 2>&1; then
  echo "libvirt network xrdp-baf-lab already exists"
else
  virsh net-define "$NET_XML"
fi
virsh net-start xrdp-baf-lab >/dev/null 2>&1 || true
virsh net-autostart xrdp-baf-lab >/dev/null
virsh net-info xrdp-baf-lab
