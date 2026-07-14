#!/usr/bin/env bash
#
# Install the BAF UDS connector on a UDS Enterprise / OpenUDS server.
#
# Installs a self-contained venv + the broker components + the baf-uds-connect
# CLI that the UDS RDP transport calls to mint a BAF assertion and register a
# one-time Broker-RDP Handle with the target VDI. Run as root on the UDS host.
#
#   sudo packaging/uds/install.sh
#
# Then edit /etc/baf-uds/config.yaml, drop in the issuer key (and smart-card
# CA), and wire the UDS RDP transport to call:
#   /usr/local/bin/baf-uds-connect --user <username> --format cookie
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="${BAF_UDS_PREFIX:-/opt/baf-uds}"
LIB="$PREFIX/lib"
CFGDIR="/etc/baf-uds"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

echo "== installing BAF UDS connector to $PREFIX =="
install -d "$LIB" "$LIB/spec" "$LIB/reference-issuer" "$LIB/reference-broker" \
    "$CFGDIR"

# Broker components (broker-neutral; no XRDP-side code).
install -m 0644 "$ROOT/broker-auth/reference-issuer/broker_issuer.py" \
    "$LIB/reference-issuer/"
install -m 0644 "$ROOT/broker-auth/spec/broker-assertion.schema.json" \
    "$LIB/spec/"
install -m 0644 "$ROOT/broker-auth/reference-broker/smartcard_auth.py" \
    "$ROOT/broker-auth/reference-broker/smartcard_login.py" \
    "$ROOT/broker-auth/reference-broker/keycloak_auth.py" \
    "$LIB/reference-broker/"
install -m 0644 "$HERE/baf_handle_client.py" "$LIB/"
install -m 0755 "$HERE/baf-uds-connect" "$PREFIX/baf-uds-connect"

# Config template (never overwrite an existing live config).
install -m 0644 "$HERE/config.example.yaml" "$CFGDIR/config.example.yaml"
[ -f "$CFGDIR/config.yaml" ] || {
    install -m 0640 "$HERE/config.example.yaml" "$CFGDIR/config.yaml"
    echo "  wrote $CFGDIR/config.yaml (edit before use)"
}

# Self-contained venv.
echo "== creating venv =="
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet \
    "cryptography>=3.4" "jsonschema>=4.0" "PyJWT>=2.4"

# CLI wrapper.
cat > /usr/local/bin/baf-uds-connect <<WRAP
#!/bin/sh
exec "$PREFIX/venv/bin/python3" "$PREFIX/baf-uds-connect" "\$@"
WRAP
chmod 0755 /usr/local/bin/baf-uds-connect

echo
echo "== installed. Next steps: =="
echo "  1. Edit $CFGDIR/config.yaml to match the VDI [BrokerAuth] settings."
echo "  2. Place the broker signing key at the configured issuer_key path"
echo "     (its public half is the VDI TrustAnchor)."
echo "  3. Ensure the VDI handle socket is reachable (local, forwarded, or"
echo "     the C6 mTLS bridge)."
echo "  4. Test:  baf-uds-connect --user <nssuser> --format cookie"
echo "  5. Point the UDS RDP transport at baf-uds-connect (see README.md)."
