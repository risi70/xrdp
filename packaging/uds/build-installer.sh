#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SHORT_COMMIT="$(git -C "$ROOT" rev-parse --short=12 "$COMMIT")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct "$COMMIT")}"
export SOURCE_DATE_EPOCH

required=(git tar gzip sha256sum)
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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/xrdp-baf-uds.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
NAME="xrdp-baf-uds-reference-$SHORT_COMMIT"
PAYLOAD="$WORK/$NAME"
mkdir -p "$PAYLOAD"

extract_file() {
    local source_path="$1"
    local output_name="$2"
    git -C "$ROOT" show "$COMMIT:$source_path" > "$PAYLOAD/$output_name"
}

extract_file packaging/uds/README.md README.md
extract_file packaging/uds/install.sh install.sh
extract_file packaging/uds/baf-uds-register baf-uds-register
extract_file broker-auth/tools/baf_handle_client.py baf_handle_client.py
chmod 0755 "$PAYLOAD/install.sh" "$PAYLOAD/baf-uds-register"

(
    cd "$PAYLOAD"
    sha256sum README.md install.sh baf-uds-register baf_handle_client.py \
        > MANIFEST.sha256
)

ARTIFACT="$OUT/$NAME.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 \
    --numeric-owner -C "$WORK" -cf - "$NAME" | gzip -n > "$ARTIFACT"
sha256sum "$ARTIFACT" > "$ARTIFACT.sha256"
tar -tzf "$ARTIFACT" > "$ARTIFACT.contents"

printf 'Built %s\n' "$ARTIFACT"
