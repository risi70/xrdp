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
usage() { echo "usage: $0 openuds-broker|ubuntu-vdi-01" >&2; exit 2; }
VM=${1:-}
case "$VM" in openuds-broker|ubuntu-vdi-01) ;; *) usage ;; esac
ROOT=$(lab_root)
require_cmd virsh
require_cmd qemu-system-x86_64
require_cmd cloud-localds
require_cmd qemu-img
IMAGE_SRC=${UBUNTU_CLOUD_IMAGE:-$ROOT/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img}
[ -f "$IMAGE_SRC" ] || { echo "missing Ubuntu cloud image: $IMAGE_SRC" >&2; exit 2; }
PUBKEY=${LAB_SSH_PUBKEY:-}
if [ -z "$PUBKEY" ]; then
  for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    [ -f "$candidate" ] && PUBKEY=$candidate && break
  done
fi
[ -f "${PUBKEY:-}" ] || { echo "missing SSH public key; set LAB_SSH_PUBKEY" >&2; exit 2; }
VM_KIND=openuds
[ "$VM" = ubuntu-vdi-01 ] && VM_KIND=ubuntu-vdi
ART="$ROOT/kvm/artifacts"
IMG_DIR="$ROOT/kvm/images"
mkdir -p "$ART" "$IMG_DIR"
qemu-img create -f qcow2 -F qcow2 -b "$IMAGE_SRC" "$IMG_DIR/$VM.qcow2" 40G >/dev/null
python3 - "$PUBKEY" "$ROOT/kvm/cloud-init/$VM_KIND/user-data" "$ART/$VM-user-data" <<'EOS'
import pathlib, sys
key = pathlib.Path(sys.argv[1]).read_text().strip()
template = pathlib.Path(sys.argv[2]).read_text()
pathlib.Path(sys.argv[3]).write_text(template.replace('$LAB_SSH_PUBLIC_KEY', key))
EOS
cloud-localds "$ART/$VM-seed.iso" "$ART/$VM-user-data" "$ROOT/kvm/cloud-init/$VM_KIND/meta-data"
sed -e "s|__LAB_IMAGE_DIR__|$IMG_DIR|g" -e "s|__LAB_ARTIFACT_DIR__|$ART|g"   "$ROOT/kvm/libvirt/domains/$VM.xml" > "$ART/$VM.xml"
virsh define "$ART/$VM.xml"
virsh start "$VM" || true
virsh dominfo "$VM"
