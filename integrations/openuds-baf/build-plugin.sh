#!/usr/bin/env bash
# Build the distributable BAFRDP plugin archive from the tracked commit.
#
# Mirrors packaging/uds/build-installer.sh: only committed files enter
# the artifact, the vendored handle client is verified against its
# origin, and the test suite must pass on the staged payload.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SHORT_COMMIT="$(git -C "$ROOT" rev-parse --short=12 "$COMMIT")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct "$COMMIT")}"
export SOURCE_DATE_EPOCH

required=(git tar gzip sha256sum msgfmt python3)
for command_name in "${required[@]}"; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'missing build command: %s\n' "$command_name" >&2
        exit 1
    }
done

if [[ -L "$OUT" ]]; then
    printf 'refusing to replace symlinked output directory: %s\n' "$OUT" >&2
    exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/xrdp-baf-openuds.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
NAME="xrdp-baf-openuds-plugin-$SHORT_COMMIT"
PAYLOAD="$WORK/$NAME"
mkdir -p "$PAYLOAD"

git -C "$ROOT" archive "$COMMIT" integrations/openuds-baf \
    | tar -x --strip-components=2 -C "$PAYLOAD"

# The vendored handle client must match its origin at the same commit.
if ! diff <(git -C "$ROOT" show \
        "$COMMIT:broker-auth/tools/baf_handle_client.py") \
        <(tail -n +4 "$PAYLOAD/BAFRDP/core/handle_socket.py") >/dev/null
then
    printf 'vendored handle_socket.py drifted from broker-auth/tools\n' >&2
    exit 1
fi

for po in "$PAYLOAD"/BAFRDP/locale/*/LC_MESSAGES/django.po; do
    msgfmt --check -o /dev/null "$po" 2>/dev/null
done

(cd "$PAYLOAD" && python3 -m pytest tests -q)
find "$PAYLOAD" -name '__pycache__' -type d -exec rm -rf {} +
rm -rf "$PAYLOAD/.pytest_cache"

(
    cd "$PAYLOAD"
    find BAFRDP tools install.sh README.md -type f | LC_ALL=C sort \
        | xargs sha256sum > MANIFEST.sha256
)

ARTIFACT="$OUT/$NAME.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 \
    --numeric-owner -C "$WORK" -cf - "$NAME" | gzip -n > "$ARTIFACT"
sha256sum "$ARTIFACT" > "$ARTIFACT.sha256"
tar -tzf "$ARTIFACT" > "$ARTIFACT.contents"

printf 'Built %s\n' "$ARTIFACT"
