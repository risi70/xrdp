#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${BAF_UDS_PREFIX:-/opt/xrdp-baf-uds-reference}"
COMMAND_LINK="${BAF_UDS_COMMAND_LINK:-/usr/local/bin/baf-uds-register}"

if [[ "$(id -u)" -ne 0 ]]; then
    printf 'run as root\n' >&2
    exit 1
fi
command -v python3 >/dev/null 2>&1 || {
    printf 'python3 is required\n' >&2
    exit 1
}

install -d -m 0755 "$PREFIX"
install -m 0755 "$HERE/baf-uds-register" "$PREFIX/baf-uds-register"
install -m 0644 "$HERE/baf_handle_client.py" "$PREFIX/baf_handle_client.py"
install -m 0644 "$HERE/README.md" "$PREFIX/README.md"
install -d -m 0755 "$(dirname "$COMMAND_LINK")"
ln -sfn "$PREFIX/baf-uds-register" "$COMMAND_LINK"

printf 'Installed the reference registration helper at %s\n' "$COMMAND_LINK"
printf '%s\n' \
    'This is not a production OpenUDS plugin and does not issue BAF assertions.' \
    "Read $PREFIX/README.md before integrating it with a trusted broker."
