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
REPORT_DIR="$ROOT/phase6/reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/phase6-$(date -u +%Y%m%dT%H%M%SZ).txt"
for cmd in virsh qemu-system-x86_64 cloud-localds ansible-playbook ssh xfreerdp; do
  require_cmd "$cmd"
done
{
  echo "Phase 6 KVM test report"
  date -u
  echo
  echo "== libvirt network =="
  virsh net-info xrdp-baf-lab || echo "SKIP: xrdp-baf-lab network is not defined"
  echo
  echo "== domains =="
  for vm in openuds-broker ubuntu-vdi-01; do
    virsh dominfo "$vm" || echo "SKIP: $vm is not defined"
  done
  echo
  echo "== ansible verify =="
  ansible-playbook --syntax-check "$ROOT/kvm/ansible/playbooks/verify.yml" -i "$ROOT/kvm/ansible/inventory.example.ini"
  if ansible all -i "$ROOT/kvm/ansible/inventory.example.ini" -m ping >/tmp/phase6-ansible-ping.log 2>&1; then
    ansible-playbook "$ROOT/kvm/ansible/playbooks/verify.yml" -i "$ROOT/kvm/ansible/inventory.example.ini"
  else
    cat /tmp/phase6-ansible-ping.log
    echo "SKIP: VMs are not reachable; provisioning-dependent checks were not run."
  fi
  echo
  echo "== phase6 static tests =="
  python3 -m unittest discover -s "$ROOT/phase6/tests" -p 'test_*.py'
  echo
  echo "== xfreerdp RDSAAD boundary =="
  rc=0
  "$ROOT/kvm/scripts/run-xfreerdp-test.sh" --target ubuntu-vdi-01 --user bafuser --mode rdsaad || rc=$?
  if [ "$rc" = 77 ]; then
    echo "SKIP: RDSAAD client injection unsupported by stock xfreerdp."
  elif [ "$rc" != 0 ]; then
    exit "$rc"
  fi
} | tee "$REPORT"
echo "Report written to $REPORT"
