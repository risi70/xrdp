#!/usr/bin/env bash
#
# Assemble the dist/ binary-artifact directory.
#
#   1. builds the .deb packages via packaging/deb/build-deb.sh (run on the
#      target Ubuntu release), then copies them here;
#   2. builds the self-contained UDS connector installer tarball;
#   3. regenerates SHA256SUMS.
#
# Run on the target Ubuntu release (packages are release-specific).
#   dist/make-dist.sh                 # build debs + tarball + checksums
#   dist/make-dist.sh --tarball-only  # skip the deb build (reuse existing debs)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VER="$(sed -nE 's/^AC_INIT\(\[xrdp\], \[([^]]+)\].*/\1/p' "$ROOT/configure.ac")~baf1"

if [ "${1:-}" != "--tarball-only" ]; then
    echo "== building .deb packages =="
    "$ROOT/packaging/deb/build-deb.sh"
    cp "$ROOT/packaging/deb/out/"*.deb "$HERE/"
fi

echo "== building UDS connector installer tarball =="
# Self-contained: exactly the files packaging/uds/install.sh reads, laid out in
# repo-relative structure so its ROOT=../.. resolution works after extraction.
tar czf "$HERE/baf-uds-connector_${VER}.tar.gz" -C "$ROOT" \
    --transform "s,^,baf-uds-connector/," --owner=0 --group=0 \
    packaging/uds/install.sh \
    packaging/uds/baf-uds-connect \
    packaging/uds/baf_handle_client.py \
    packaging/uds/config.example.yaml \
    packaging/uds/README.md \
    broker-auth/reference-issuer/broker_issuer.py \
    broker-auth/reference-broker/smartcard_auth.py \
    broker-auth/reference-broker/smartcard_login.py \
    broker-auth/reference-broker/keycloak_auth.py \
    broker-auth/spec/broker-assertion.schema.json

echo "== checksums =="
( cd "$HERE" && sha256sum *.deb *.tar.gz > SHA256SUMS && cat SHA256SUMS )
echo "== done: $HERE =="
