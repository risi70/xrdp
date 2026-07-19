#!/usr/bin/env bash
# Install the BAFRDP transport into an OpenUDS / UDS Enterprise server.
#
# Copies the BAFRDP package into the server's transports tree and merges
# the shipped locale catalogs into the server's Django catalogs. Never
# restarts services on its own.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="python3"
UDS_PATH=""
LOCALES="merge"

usage() {
    cat <<'EOF'
usage: install.sh [--uds-path DIR] [--python BIN] [--locales merge|skip]

  --uds-path DIR   OpenUDS package directory (default: autodetect by
                   importing 'uds' with --python)
  --python BIN     Python interpreter of the UDS server environment
  --locales MODE   merge translated catalogs into the server catalogs
                   and recompile (default), or skip
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uds-path) UDS_PATH="${2:?}"; shift 2 ;;
        --python)   PYTHON="${2:?}"; shift 2 ;;
        --locales)  LOCALES="${2:?}"; shift 2 ;;
        *) usage ;;
    esac
done
[[ "$LOCALES" == "merge" || "$LOCALES" == "skip" ]] || usage

if [[ -z "$UDS_PATH" ]]; then
    UDS_PATH="$("$PYTHON" -c \
        'import os, uds; print(os.path.dirname(uds.__file__))')" || {
        printf 'cannot import uds with %s; pass --uds-path\n' "$PYTHON" >&2
        exit 1
    }
fi
[[ -d "$UDS_PATH/transports" ]] || {
    printf 'not an OpenUDS tree (no transports/): %s\n' "$UDS_PATH" >&2
    exit 1
}
[[ -d "$HERE/BAFRDP" ]] || {
    printf 'BAFRDP payload missing next to install.sh\n' >&2
    exit 1
}

TARGET="$UDS_PATH/transports/BAFRDP"
if [[ -e "$TARGET" ]]; then
    BACKUP="$TARGET.previous.$(date -u +%Y%m%d%H%M%S)"
    printf 'existing install moved to %s\n' "$BACKUP"
    mv "$TARGET" "$BACKUP"
fi
cp -a "$HERE/BAFRDP" "$TARGET"
find "$TARGET" -name '__pycache__' -type d -exec rm -rf {} +
"$PYTHON" -m compileall -q "$TARGET"

if [[ "$LOCALES" == "merge" ]]; then
    for po in "$TARGET"/locale/*/LC_MESSAGES/django.po; do
        lang="$(basename "$(dirname "$(dirname "$po")")")"
        server_po="$UDS_PATH/locale/$lang/LC_MESSAGES/django.po"
        server_mo="${server_po%.po}.mo"
        if [[ -f "$server_po" ]]; then
            merged="$(mktemp)"
            msgcat --use-first "$server_po" "$po" -o "$merged"
            mv "$merged" "$server_po"
            msgfmt --check -o "$server_mo" "$server_po"
            printf 'merged %s catalog into server locale\n' "$lang"
        else
            mkdir -p "$(dirname "$server_po")"
            cp "$po" "$server_po"
            msgfmt --check -o "$server_mo" "$server_po"
            printf 'installed %s catalog\n' "$lang"
        fi
    done
fi

cat <<'EOF'

BAFRDP transport installed. Next steps (manual, by design):
  1. Restart the UDS server processes so the transport registers.
  2. In the administration UI, create a transport of type
     "RDP (BAF broker)" and fill in the "BAF Broker" tab.
  3. Place the mutual-TLS material and SSH registration key under
     /etc/uds/baf/ (root-owned, mode 0600 for keys).
EOF
