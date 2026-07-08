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
for vm in ubuntu-vdi-01 openuds-broker; do
  if virsh dominfo "$vm" >/dev/null 2>&1; then
    virsh destroy "$vm" >/dev/null 2>&1 || true
    virsh undefine "$vm" --nvram >/dev/null 2>&1 || virsh undefine "$vm" >/dev/null 2>&1 || true
  fi
done
if virsh net-info xrdp-baf-lab >/dev/null 2>&1; then
  virsh net-destroy xrdp-baf-lab >/dev/null 2>&1 || true
  virsh net-undefine xrdp-baf-lab >/dev/null 2>&1 || true
fi
echo "Lab libvirt resources removed. Disk artifacts remain under $ROOT/kvm/images and $ROOT/kvm/artifacts."
