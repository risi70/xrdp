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

STATIC_ONLY=0
REQUIRE_VMS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --static-only) STATIC_ONLY=1; shift ;;
    --require-vms) REQUIRE_VMS=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROOT=$(lab_root)
REPORT_DIR="$ROOT/phase6/reports"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/phase6-$(date -u +%Y%m%dT%H%M%SZ).txt"
for cmd in virsh qemu-system-x86_64 cloud-localds ansible-playbook ssh xfreerdp; do
  require_cmd "$cmd"
done

hard_fail=0
{
  echo "Phase 6 KVM test report"
  date -u
  echo "static_only=$STATIC_ONLY"
  echo "require_vms=$REQUIRE_VMS"
  echo

  echo "== phase6 static tests =="
  bash -n "$ROOT"/kvm/scripts/*.sh
  ansible-playbook --syntax-check "$ROOT/kvm/ansible/playbooks/site.yml" -i "$ROOT/kvm/ansible/inventory.example.ini"
  python3 -m unittest discover -s "$ROOT/phase6/tests" -p 'test_*.py'

  if [ "$STATIC_ONLY" = 1 ]; then
    echo "SKIP: static-only mode requested; VM-dependent checks were not run."
    exit 0
  fi

  echo
  echo "== libvirt network =="
  if virsh net-info xrdp-baf-lab; then
    echo "network=present"
  else
    echo "network=skip_missing"
    [ "$REQUIRE_VMS" = 1 ] && hard_fail=1
  fi

  echo
  echo "== domains =="
  for vm in openuds-broker ubuntu-vdi-01; do
    if virsh dominfo "$vm"; then
      echo "$vm=present"
    else
      echo "$vm=skip_missing"
      [ "$REQUIRE_VMS" = 1 ] && hard_fail=1
    fi
  done

  echo
  echo "== ansible verify =="
  ansible-playbook --syntax-check "$ROOT/kvm/ansible/playbooks/verify.yml" -i "$ROOT/kvm/ansible/inventory.example.ini"
  if ansible all -i "$ROOT/kvm/ansible/inventory.example.ini" -m ping >/tmp/phase6-ansible-ping.log 2>&1; then
    ansible-playbook "$ROOT/kvm/ansible/playbooks/verify.yml" -i "$ROOT/kvm/ansible/inventory.example.ini"
  else
    cat /tmp/phase6-ansible-ping.log
    echo "ansible_vm_verify=skip_unreachable"
    [ "$REQUIRE_VMS" = 1 ] && hard_fail=1
  fi

  echo
  echo "== xfreerdp RDSAAD boundary =="
  rc=0
  "$ROOT/kvm/scripts/run-xfreerdp-test.sh" --target ubuntu-vdi-01 --user bafuser --mode rdsaad || rc=$?
  if [ "$rc" = 77 ]; then
    echo "xfreerdp_rdsaad=skip_stock_client"
  elif [ "$rc" != 0 ]; then
    hard_fail=1
  fi

  if [ "$hard_fail" != 0 ]; then
    echo "phase6_status=failed_required_vm_check"
    exit 1
  fi
  echo "phase6_status=pass_with_optional_skips"
} | tee "$REPORT"
echo "Report written to $REPORT"
