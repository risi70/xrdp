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
HOST=${1:-}
[ -n "$HOST" ] || { echo "usage: $0 host-or-ip [timeout_seconds]" >&2; exit 2; }
TIMEOUT=${2:-180}
require_cmd ssh
end=$((SECONDS + TIMEOUT))
until ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "ansible@$HOST" true >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$end" ]; then
    echo "SSH not reachable: $HOST" >&2
    exit 1
  fi
  sleep 5
done
echo "SSH reachable: $HOST"
