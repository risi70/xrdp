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
REPO=$(repo_root)
"$ROOT/kvm/scripts/check-prereqs.sh"
"$ROOT/kvm/scripts/create-network.sh"
"$ROOT/kvm/scripts/create-vm.sh" openuds-broker
"$ROOT/kvm/scripts/create-vm.sh" ubuntu-vdi-01
"$ROOT/kvm/scripts/wait-for-ssh.sh" 192.168.126.10
"$ROOT/kvm/scripts/wait-for-ssh.sh" 192.168.126.20
"$ROOT/kvm/scripts/sync-source.sh" 192.168.126.20 /opt/xrdp-src
ANSIBLE_CONFIG="$REPO/ansible.cfg" ansible-playbook   -i "$ROOT/kvm/ansible/inventory.example.ini"   "$ROOT/kvm/ansible/playbooks/site.yml"
