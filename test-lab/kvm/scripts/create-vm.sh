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

run_priv() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

prepare_storage_dir() {
  local dir=$1
  if [ -d "$dir" ] && [ -w "$dir" ]; then
    return 0
  fi
  if getent group kvm >/dev/null 2>&1; then
    run_priv install -d -m 0775 -g kvm "$dir"
  else
    run_priv install -d -m 0775 "$dir"
  fi
}

install_for_qemu() {
  local path=$1
  if getent group kvm >/dev/null 2>&1; then
    run_priv chgrp kvm "$path" || true
  fi
  run_priv chmod g+rw,o+r "$path"
}

VM=${1:-}
case "$VM" in openuds-broker|ubuntu-vdi-01) ;; *) usage ;; esac
ROOT=$(lab_root)
require_cmd virsh
require_cmd qemu-system-x86_64
require_cmd cloud-localds
require_cmd qemu-img
require_cmd sudo

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

LOCAL_ART="$ROOT/kvm/artifacts"
STORAGE_DIR=${LIBVIRT_LAB_STORAGE_DIR:-/var/lib/libvirt/images/xrdp-baf-lab}
BASE_IMAGE="$STORAGE_DIR/$(basename "$IMAGE_SRC")"
VM_DISK="$STORAGE_DIR/$VM.qcow2"
SEED_ISO="$STORAGE_DIR/$VM-seed.iso"
mkdir -p "$LOCAL_ART"
prepare_storage_dir "$STORAGE_DIR"

if [ ! -f "$BASE_IMAGE" ] || ! cmp -s "$IMAGE_SRC" "$BASE_IMAGE"; then
  echo "Installing base image for libvirt access: $BASE_IMAGE"
  run_priv cp "$IMAGE_SRC" "$BASE_IMAGE"
  install_for_qemu "$BASE_IMAGE"
fi

if [ -f "$VM_DISK" ]; then
  echo "VM disk already exists: $VM_DISK"
else
  echo "Creating VM disk: $VM_DISK"
  if [ -w "$STORAGE_DIR" ]; then
    qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$VM_DISK" 40G >/dev/null
  else
    run_priv qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$VM_DISK" 40G >/dev/null
  fi
  install_for_qemu "$VM_DISK"
fi

python3 - "$PUBKEY" "$ROOT/kvm/cloud-init/$VM_KIND/user-data" "$LOCAL_ART/$VM-user-data" <<'EOS'
import pathlib, sys
key = pathlib.Path(sys.argv[1]).read_text().strip()
template = pathlib.Path(sys.argv[2]).read_text()
pathlib.Path(sys.argv[3]).write_text(template.replace('$LAB_SSH_PUBLIC_KEY', key))
EOS

TMP_SEED="$LOCAL_ART/$VM-seed.iso"
cloud-localds "$TMP_SEED" "$LOCAL_ART/$VM-user-data" "$ROOT/kvm/cloud-init/$VM_KIND/meta-data"
run_priv cp "$TMP_SEED" "$SEED_ISO"
install_for_qemu "$SEED_ISO"

sed -e "s|__LAB_IMAGE_DIR__|$STORAGE_DIR|g" -e "s|__LAB_ARTIFACT_DIR__|$STORAGE_DIR|g"   "$ROOT/kvm/libvirt/domains/$VM.xml" > "$LOCAL_ART/$VM.xml"

if virsh dominfo "$VM" >/dev/null 2>&1; then
  echo "Domain already defined: $VM"
else
  virsh define "$LOCAL_ART/$VM.xml"
fi
virsh start "$VM" || true
virsh dominfo "$VM"
