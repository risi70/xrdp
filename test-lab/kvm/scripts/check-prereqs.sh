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
for cmd in virsh qemu-system-x86_64 cloud-localds qemu-img ansible-playbook ssh xfreerdp rsync; do
  if ! require_cmd "$cmd"; then
    status=1
  fi
done

if [ -e /dev/kvm ]; then
  echo "KVM device: /dev/kvm present"
else
  echo "missing KVM device: /dev/kvm" >&2
  status=1
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet libvirtd || systemctl is-active --quiet virtqemud; then
    echo "libvirt daemon: active"
  else
    echo "libvirt daemon is not active (checked libvirtd and virtqemud)" >&2
    status=1
  fi
else
  echo "systemctl unavailable; cannot verify libvirt daemon" >&2
fi

if id -nG | tr ' ' '
' | grep -Eq '^(libvirt|kvm)$'; then
  echo "user groups: libvirt/kvm membership present"
else
  echo "current user is not in libvirt or kvm group; virsh/KVM access may fail" >&2
fi

image=${UBUNTU_CLOUD_IMAGE:-$ROOT/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img}
if [ -f "$image" ]; then
  echo "Ubuntu cloud image: $image"
else
  echo "missing Ubuntu cloud image: $image" >&2
  status=1
fi

pubkey=${LAB_SSH_PUBKEY:-}
if [ -z "$pubkey" ]; then
  for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    [ -f "$candidate" ] && pubkey=$candidate && break
  done
fi
if [ -f "${pubkey:-}" ]; then
  echo "SSH public key: $pubkey"
else
  echo "missing SSH public key; set LAB_SSH_PUBKEY" >&2
  status=1
fi

exit "$status"
