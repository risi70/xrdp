#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SHORT_COMMIT="$(git -C "$ROOT" rev-parse --short=12 "$COMMIT")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct "$COMMIT")}"
export SOURCE_DATE_EPOCH

required=(autoconf automake libtoolize pkg-config make gcc git tar dpkg-deb
          dpkg-shlibdeps dpkg-architecture readelf sha256sum grep)
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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/xrdp-baf-deb.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/src"
STAGE="$WORK/stage"
mkdir -p "$SRC" "$STAGE"

# git archive excludes untracked private files, caches, and previous artifacts.
git -C "$ROOT" archive "$COMMIT" | tar -xf - -C "$SRC"
for submodule in libpainter librfxcodec; do
    read -r _mode _type object _path < <(git -C "$ROOT" ls-tree "$COMMIT" -- "$submodule")
    git -C "$ROOT/$submodule" cat-file -e "$object^{commit}" 2>/dev/null || {
        printf 'submodule %s does not contain required commit %s\n' \
            "$submodule" "$object" >&2
        exit 1
    }
    mkdir -p "$SRC/$submodule"
    git -C "$ROOT/$submodule" archive "$object" | tar -xf - -C "$SRC/$submodule"
done

VERSION="$(
    while IFS= read -r line; do
        if [[ "$line" =~ ^AC_INIT\(\[xrdp\],\ \[([^]]+)\] ]]; then
            printf '%s' "${BASH_REMATCH[1]}"
            break
        fi
    done < "$SRC/configure.ac"
)"
[[ -n "$VERSION" ]] || { printf 'unable to determine XRDP version\n' >&2; exit 1; }
ARCH="$(dpkg-architecture -qDEB_HOST_ARCH)"
DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d)"
PACKAGE_VERSION="${VERSION}+baf1.${DATE}.${SHORT_COMMIT}"

printf 'Building xrdp-baf %s for %s from %s\n' \
    "$PACKAGE_VERSION" "$ARCH" "$COMMIT"

(
    cd "$SRC"
    ./bootstrap
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --runstatedir=/run \
        --with-socketdir=/run/xrdp \
        --with-systemdsystemunitdir=/lib/systemd/system \
        --enable-pam \
        --enable-broker-auth \
        --enable-smartcard \
        --disable-rfxcodec
    make -j"${JOBS:-$(nproc)}"
    make -C tests/baf check
    make DESTDIR="$STAGE" install
)

# Upstream install creates host credentials. Never distribute build-time keys.
rm -f "$STAGE/etc/xrdp/rsakeys.ini" \
    "$STAGE/etc/xrdp/cert.pem" \
    "$STAGE/etc/xrdp/key.pem"

# This is a runtime package, not an SDK.
find "$STAGE/usr" -type f \( -name '*.a' -o -name '*.la' \) -delete
rm -rf "$STAGE/usr/include" "$STAGE/usr/lib/pkgconfig"

while IFS= read -r -d '' packaged_file; do
    if grep -Iq . "$packaged_file" && \
       grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "$packaged_file"; then
        printf 'refusing to package private key material: %s\n' \
            "$packaged_file" >&2
        exit 1
    fi
done < <(find "$STAGE" -type f -print0)

install -D -m 0644 "$HERE/xrdp-baf-replayd.service" \
    "$STAGE/lib/systemd/system/xrdp-baf-replayd.service"
install -D -m 0644 "$HERE/xrdp-baf-handled.service" \
    "$STAGE/lib/systemd/system/xrdp-baf-handled.service"
install -D -m 0644 "$SRC/broker-auth/DEPLOYMENT-KEYCLOAK-BAF-XRDP.md" \
    "$STAGE/usr/share/doc/xrdp-baf/DEPLOYMENT-KEYCLOAK-BAF-XRDP.md"
install -D -m 0644 "$HERE/README.md" \
    "$STAGE/usr/share/doc/xrdp-baf/PACKAGING.md"

mkdir -p "$SRC/debian" "$STAGE/DEBIAN"
printf '%s\n' \
    'Source: xrdp-baf' \
    'Section: net' \
    'Priority: optional' \
    'Maintainer: XRDP BAF maintainers <xrdp-devel@googlegroups.com>' \
    'Standards-Version: 4.6.2' \
    '' \
    'Package: xrdp-baf' \
    'Architecture: any' \
    'Description: XRDP with build-gated Broker Authentication Framework support' \
    > "$SRC/debian/control"

elf_files=()
while IFS= read -r -d '' candidate; do
    if readelf -h "$candidate" >/dev/null 2>&1; then
        elf_files+=("$candidate")
    fi
done < <(find "$STAGE/usr" -type f -print0)
[[ ${#elf_files[@]} -gt 0 ]] || { printf 'no packaged ELF files found\n' >&2; exit 1; }

library_args=()
while IFS= read -r -d '' library_dir; do
    library_args+=("-l$library_dir")
done < <(find "$STAGE/usr/lib" -type d -print0)

dependency_line="$(
    cd "$SRC"
    dpkg-shlibdeps -O "${library_args[@]}" "${elf_files[@]}"
)"
dependencies="${dependency_line#shlibs:Depends=}"
[[ -n "$dependencies" && "$dependencies" != "$dependency_line" ]] || {
    printf 'unable to resolve package shared-library dependencies\n' >&2
    exit 1
}

installed_size="$(du -sk "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: xrdp-baf
Version: $PACKAGE_VERSION
Architecture: $ARCH
Maintainer: XRDP BAF maintainers <xrdp-devel@googlegroups.com>
Installed-Size: $installed_size
Depends: $dependencies, adduser, openssl
Recommends: xorgxrdp
Provides: xrdp
Conflicts: xrdp
Replaces: xrdp
Section: net
Priority: optional
X-BAF-Git-Commit: $COMMIT
Description: XRDP with Broker Authentication Framework support
 XRDP remote desktop server compiled with the experimental, build-gated BAF
 assertion validator and trusted replay and Broker-RDP Handle services.
 Broker authentication and its services remain disabled after installation;
 classic username/password PAM login behavior is preserved.
CONTROL

(
    cd "$STAGE"
    find etc/xrdp -type f -printf '/%p\n' | LC_ALL=C sort > DEBIAN/conffiles
)
install -m 0755 "$HERE/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$HERE/postrm" "$STAGE/DEBIAN/postrm"
find "$STAGE" -type d -exec chmod 0755 {} +

PACKAGE="$OUT/xrdp-baf_${PACKAGE_VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$PACKAGE"
sha256sum "$PACKAGE" > "$PACKAGE.sha256"
dpkg-deb --contents "$PACKAGE" > "$PACKAGE.contents"
dpkg-deb --info "$PACKAGE" > "$PACKAGE.info"

printf 'Built %s\n' "$PACKAGE"
