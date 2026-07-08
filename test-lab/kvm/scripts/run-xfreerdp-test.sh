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
TARGET=ubuntu-vdi-01
USER=bafuser
MODE=classic
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET=$2; shift 2 ;;
    --user) USER=$2; shift 2 ;;
    --mode) MODE=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
require_cmd xfreerdp
case "$MODE" in
  classic)
    echo "Running xfreerdp reachability test for $TARGET as $USER."
    echo "Set PHASE6_RDP_PASSWORD for non-interactive classic login."
    if [ -n "${PHASE6_RDP_PASSWORD:-}" ]; then
      xfreerdp /v:"$TARGET" /u:"$USER" /p:"$PHASE6_RDP_PASSWORD" /cert:ignore +auto-reconnect /timeout:15000 || exit $?
    else
      xfreerdp /v:"$TARGET" /u:"$USER" /cert:ignore /timeout:15000 || exit $?
    fi
    ;;
  rdsaad)
    echo "SKIP: stock xfreerdp does not expose arbitrary rdp_assertion injection for this lab."
    echo "Use Mode B gateway testing or a patched RDSAAD-capable client for full wire-level assertion injection."
    exit 77
    ;;
  *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac
