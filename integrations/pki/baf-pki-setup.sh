#!/usr/bin/env bash
# X.509 and key setup for the BAF end-to-end chain.
#
# Implements the credential inventory of
# broker-auth/DEPLOYMENT-PKI-CREDENTIALS.md (K1-K11) and emits one
# ready-to-copy bundle per host. Two modes of obtaining certificates:
#
#   init-ca   create a lab CA hierarchy (root + TLS issuing CA +
#             client-auth issuing CA) standing in for the central PKI
#   issue     generate all keys and sign leaf certificates with the
#             lab CAs from init-ca
#   csr       generate all keys and CSRs only, for submission to the
#             real central PKI (no CA material created)
#
# Private keys are created 0600 and never leave the output directory.
set -euo pipefail
umask 077

usage() {
    cat <<'EOF'
usage:
  baf-pki-setup.sh init-ca --out DIR
  baf-pki-setup.sh issue   --ca DIR --config FILE --out DIR
  baf-pki-setup.sh csr     --config FILE --out DIR

The config file is a shell-style key=value file; see pki.conf.example.
EOF
    exit 2
}

# --- defaults, overridden by --config ------------------------------------
BROKER_FQDN=""
UDS_FQDN=""
KEYCLOAK_FQDN=""
VDI_HOSTS=""
CLIENT_CN="uds-server"
KID="baf-signing-key-01"
SSH_USER="baf-register"
HANDLE_TARGET_TTL="90"
LEAF_DAYS="90"
CA_DAYS="3650"

MODE="${1:-}"; shift || usage
CA_DIR=""; OUT=""; CONFIG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca)     CA_DIR="${2:?}"; shift 2 ;;
        --out)    OUT="${2:?}"; shift 2 ;;
        --config) CONFIG="${2:?}"; shift 2 ;;
        *) usage ;;
    esac
done

require_config() {
    [[ -n "$CONFIG" && -f "$CONFIG" ]] || {
        printf 'missing --config file\n' >&2; exit 1; }
    # shellcheck disable=SC1090
    source "$CONFIG"
    for name in BROKER_FQDN UDS_FQDN KEYCLOAK_FQDN VDI_HOSTS; do
        [[ -n "${!name}" ]] || {
            printf 'config must set %s\n' "$name" >&2; exit 1; }
    done
}

require_out() {
    [[ -n "$OUT" ]] || { printf 'missing --out\n' >&2; exit 1; }
    mkdir -p "$OUT"
}

ec_key() { openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

# --- CA hierarchy (lab stand-in for the central PKI) ----------------------

sign_ca() { # csr out issuer_cert issuer_key pathlen
    openssl x509 -req -in "$1" -out "$2" -CA "$3" -CAkey "$4" \
        -CAcreateserial -days "$CA_DAYS" -sha256 \
        -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:%s\nkeyUsage=critical,keyCertSign,cRLSign\n' "$5")
}

init_ca() {
    require_out
    local ca="$OUT"
    ec_key "$ca/root-ca.key"
    openssl req -new -x509 -key "$ca/root-ca.key" -out "$ca/root-ca.pem" \
        -days "$CA_DAYS" -sha256 -subj "/CN=BAF Lab Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    for name in tls client; do
        local cn="BAF Lab TLS Issuing CA"
        [[ "$name" == client ]] && cn="BAF Lab Client Issuing CA"
        ec_key "$ca/$name-ca.key"
        openssl req -new -key "$ca/$name-ca.key" -subj "/CN=$cn" \
            -out "$ca/$name-ca.csr"
        sign_ca "$ca/$name-ca.csr" "$ca/$name-ca.pem" \
            "$ca/root-ca.pem" "$ca/root-ca.key" 0
        cat "$ca/$name-ca.pem" "$ca/root-ca.pem" > "$ca/$name-ca-chain.pem"
        rm "$ca/$name-ca.csr"
    done
    printf 'lab CA hierarchy created in %s\n' "$ca"
}

# --- leaf issuance --------------------------------------------------------

leaf_csr() { # key_out csr_out subject_cn [san]
    ec_key "$1"
    if [[ -n "${4:-}" ]]; then
        openssl req -new -key "$1" -out "$2" -subj "/CN=$3" \
            -addext "subjectAltName=$4"
    else
        openssl req -new -key "$1" -out "$2" -subj "/CN=$3"
    fi
}

sign_leaf() { # csr cert_out eku [san]
    local ext="basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$3"
    [[ -n "${4:-}" ]] && ext+=$'\n'"subjectAltName=$4"
    local ca="tls"
    [[ "$3" == "clientAuth" ]] && ca="client"
    openssl x509 -req -in "$1" -out "$2" -CA "$CA_DIR/$ca-ca.pem" \
        -CAkey "$CA_DIR/$ca-ca.key" -CAcreateserial \
        -days "$LEAF_DAYS" -sha256 -extfile <(printf '%s\n' "$ext")
}

make_leaf() { # dir basename cn eku [san]  -> key + (issue: cert / csr: csr)
    mkdir -p "$1"
    leaf_csr "$1/$2.key" "$1/$2.csr" "$3" "${5:-}"
    if [[ "$MODE" == "issue" ]]; then
        sign_leaf "$1/$2.csr" "$1/$2.pem" "$4" "${5:-}"
        rm "$1/$2.csr"
    fi
}

emit_bundles() {
    require_config
    require_out
    local broker="$OUT/broker" uds="$OUT/uds" kc="$OUT/keycloak"
    local trust="$OUT/trust"
    mkdir -p "$broker" "$uds" "$kc" "$trust"

    # K1 - BAF assertion signing pair (RSA/RS256, kid-identified).
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$broker/baf-signing.key"
    openssl pkey -in "$broker/baf-signing.key" -pubout \
        -out "$broker/baf-signing.pub"
    printf '%s\n' "$KID" > "$broker/baf-signing.kid"

    # K2 - issuance service TLS server certificate.
    make_leaf "$broker" server "$BROKER_FQDN" serverAuth \
        "DNS:$BROKER_FQDN"
    # K3 - OpenUDS mTLS client certificate (CN = allowed_client_cn).
    make_leaf "$uds" uds-client "$CLIENT_CN" clientAuth
    # K4 - OpenUDS portal TLS certificate.
    make_leaf "$uds" portal-server "$UDS_FQDN" serverAuth "DNS:$UDS_FQDN"
    # K6 - Keycloak TLS certificate.
    make_leaf "$kc" server "$KEYCLOAK_FQDN" serverAuth \
        "DNS:$KEYCLOAK_FQDN"

    # K10 - handle-registration SSH keypair.
    ssh-keygen -q -t ed25519 -N "" -C "$SSH_USER" \
        -f "$uds/registrar_ed25519"

    if [[ "$MODE" == "issue" ]]; then
        cp "$CA_DIR/client-ca-chain.pem" "$broker/clients-ca.pem"
        cp "$CA_DIR/tls-ca-chain.pem" "$uds/broker-ca.pem"
        cp "$CA_DIR/root-ca.pem" "$trust/root-ca.pem"
    fi

    # Per-VDI-host bundles: K9 + TrustAnchor + authorized_keys snippet.
    local registrar_pub
    registrar_pub="$(cat "$uds/registrar_ed25519.pub")"
    for host in $VDI_HOSTS; do
        local dir="$OUT/vdi-$host"
        mkdir -p "$dir"
        make_leaf "$dir" cert "$host" serverAuth "DNS:$host"
        mv "$dir/cert.key" "$dir/key.pem"
        cp "$broker/baf-signing.pub" "$dir/baf-broker-public.pem"
        printf 'command="baf-uds-register --target %s --ttl %s --format json",restrict %s\n' \
            "$host" "$HANDLE_TARGET_TTL" "$registrar_pub" \
            > "$dir/authorized_keys.snippet"
        cat > "$dir/README" <<EOF
Install on VDI host $host:
  cert.pem, key.pem        -> /etc/xrdp/ (xrdp.ini: certificate=, key_file=)
  baf-broker-public.pem    -> /etc/xrdp/ (sesman.ini TrustAnchor, KeyId=$KID)
  authorized_keys.snippet  -> ~$SSH_USER/.ssh/authorized_keys
Then run on the OpenUDS server to pin the host key (K11):
  ssh-keyscan -t ed25519 $host >> /etc/uds/baf/known_hosts
EOF
    done

    cat > "$broker/README" <<EOF
Install on the broker host (issuance service):
  server.pem, server.key   -> /etc/xrdp-baf/issuanced/ (tls_cert, tls_key)
  clients-ca.pem           -> /etc/xrdp-baf/issuanced/ (client_ca)
  baf-signing.key/.pub     -> /etc/xrdp-baf/issuanced/ (private_key; kid=$KID)
allowed_client_cn must include: $CLIENT_CN
EOF
    cat > "$uds/README" <<EOF
Install on the OpenUDS server:
  uds-client.pem/.key      -> /etc/uds/baf/ (transport client cert/key)
  broker-ca.pem            -> /etc/uds/baf/ (transport "Broker CA bundle")
  portal-server.pem/.key   -> web server TLS
  registrar_ed25519(.pub)  -> /etc/uds/baf/ (transport "SSH identity file")
Populate /etc/uds/baf/known_hosts with ssh-keyscan (see VDI READMEs).
EOF
    printf '%s complete: bundles in %s\n' "$MODE" "$OUT"
}

case "$MODE" in
    init-ca) init_ca ;;
    issue)
        [[ -n "$CA_DIR" && -f "$CA_DIR/tls-ca.pem" ]] || {
            printf 'issue needs --ca DIR from init-ca\n' >&2; exit 1; }
        emit_bundles ;;
    csr) emit_bundles ;;
    *) usage ;;
esac
