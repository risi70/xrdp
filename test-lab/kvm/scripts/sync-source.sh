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
ROOT=$(repo_root)
TARGET=${1:-ubuntu-vdi-01}
DEST=${2:-/opt/xrdp-src}
USER_NAME=${PHASE6_SSH_USER:-ansible}
require_cmd rsync
require_cmd ssh
rsync -az --delete   --exclude .git   --exclude autom4te.cache   --exclude '**/.libs'   --exclude '**/*.o'   --exclude '**/*.lo'   --exclude '**/*.la'   --exclude 'test-lab/kvm/images/*'   --exclude 'test-lab/kvm/isos/*'   --exclude 'test-lab/kvm/artifacts/*'   --exclude 'test-lab/phase6/reports/*'   --exclude '__pycache__'   --exclude '*.pyc'   "$ROOT/" "$USER_NAME@$TARGET:$DEST/"
echo "Source synchronized to $USER_NAME@$TARGET:$DEST"
