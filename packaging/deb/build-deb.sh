#!/usr/bin/env bash
#
# Build Debian packages for the broker-authenticated XRDP (BAF) solution.
#
# Produces two .deb files under packaging/deb/out/:
#   xrdp-baf_<ver>_<arch>.deb      - patched XRDP + BAF services (replaces xrdp)
#   xorgxrdp-baf_<ver>_<arch>.deb  - matching xorgxrdp video/input drivers
#
# Works on Ubuntu 24.04 (noble) and 26.04. Run it ON the target Ubuntu
# release (packages are release-specific: build on 24.04 for 24.04, on 26.04
# for 26.04). Requires the build toolchain and dpkg-deb.
#
#   sudo apt-get install build-essential autoconf automake libtool pkg-config \
#     libssl-dev libpam0g-dev libx11-dev libxfixes-dev libxrandr-dev \
#     libxkbfile-dev libpixman-1-dev libsm-dev libice-dev libjwt-dev \
#     libjansson-dev nasm git xserver-xorg-dev dpkg-dev
#
# Usage: packaging/deb/build-deb.sh [--skip-xorgxrdp]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"; rm -rf "$OUT"; mkdir -p "$OUT"

# Resolve runtime package dependencies for a staged tree without a debian/
# dir: ldd every ELF, map each shared object to its owning package. Release-
# accurate (works on 24.04 and 26.04). Never fails the build.
compute_deps() {
    local stage="$1" self="${2:-xrdp}"
    { find "$stage/usr" -type f \( -perm -u+x -o -name '*.so*' \) 2>/dev/null \
        | while read -r f; do ldd "$f" 2>/dev/null | awk '/=> \//{print $3}'; done; } \
      | sort -u \
      | while read -r lib; do dpkg -S "$(readlink -f "$lib")" 2>/dev/null | cut -d: -f1; done \
      | tr ',' '\n' | sed 's/^ *//' | sort -u \
      | grep -vE "^($self|xorgxrdp)" | paste -sd, | sed 's/,/, /g' || true
}
ARCH="$(dpkg --print-architecture)"
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-unknown}")"
VER="$(sed -nE 's/^AC_INIT\(\[xrdp\], \[([^]]+)\].*/\1/p' "$ROOT/configure.ac")"
PKGVER="${VER}~baf1+${CODENAME}"
SKIP_XORG=0
[ "${1:-}" = "--skip-xorgxrdp" ] && SKIP_XORG=1

echo "== building xrdp-baf ${PKGVER} (${ARCH}) =="

# --- 1. Build XRDP + BAF into a staging tree (system prefix) --------------
# Build in a pristine copy so stale libtool state from an in-tree /usr/local
# build cannot leak (and so the source tree is left untouched).
STAGE="$OUT/xrdp-baf"
BUILD="$OUT/build"
rsync -a --exclude '.git' --exclude autom4te.cache --exclude '**/.libs' \
    --exclude '**/*.o' --exclude '**/*.lo' --exclude '**/*.la' \
    --exclude 'Makefile' --exclude 'Makefile.in' --exclude 'config.status' \
    --exclude 'config.log' --exclude 'config_ac.h' --exclude 'stamp-h1' \
    --exclude 'libtool' --exclude 'packaging/deb/out' "$ROOT/" "$BUILD/"
cd "$BUILD"
./bootstrap
./configure --enable-broker-auth --disable-rfxcodec \
    --prefix=/usr --sysconfdir=/etc --localstatedir=/var >/dev/null
make -j"$(nproc)"
rm -rf "$STAGE"; make install DESTDIR="$STAGE" >/dev/null

# --- 2. systemd units for the BAF trusted services -----------------------
install -d "$STAGE/lib/systemd/system"
cat > "$STAGE/lib/systemd/system/xrdp-baf-replayd.service" <<'UNIT'
[Unit]
Description=XRDP BAF trusted replay service
After=network.target
Before=xrdp-sesman.service
[Service]
ExecStart=/usr/sbin/xrdp-baf-replayd -s /run/xrdp-baf/replay.sock
Restart=on-failure
RuntimeDirectory=xrdp-baf
RuntimeDirectoryMode=0750
[Install]
WantedBy=multi-user.target
UNIT
cat > "$STAGE/lib/systemd/system/xrdp-baf-handled.service" <<'UNIT'
[Unit]
Description=XRDP BAF one-time handle service
After=network.target
Before=xrdp-sesman.service
[Service]
ExecStart=/usr/sbin/xrdp-baf-handled -s /run/xrdp-baf/handle.sock
Restart=on-failure
RuntimeDirectory=xrdp-baf
RuntimeDirectoryMode=0750
[Install]
WantedBy=multi-user.target
UNIT

# --- 3. Debian control metadata ------------------------------------------
install -d "$STAGE/DEBIAN"
INSTALLED_KB=$(du -sk "$STAGE" | cut -f1)
DEPS="$(compute_deps "$STAGE" xrdp-baf)"
cat > "$STAGE/DEBIAN/control" <<CTRL
Package: xrdp-baf
Version: ${PKGVER}
Architecture: ${ARCH}
Maintainer: XRDP BAF <xrdp-devel@googlegroups.com>
Installed-Size: ${INSTALLED_KB}
Depends: ${DEPS:-libc6}, adduser, ssl-cert
Recommends: xorgxrdp-baf (= ${PKGVER}), xfce4, dbus-x11, sssd
Provides: xrdp
Conflicts: xrdp
Replaces: xrdp
Section: net
Priority: optional
Description: XRDP with the Broker Authentication Framework (BAF)
 Remote desktop server with broker-authenticated pre-logon (Mode C) support:
 clients present a single-use handle issued by a trusted broker, which XRDP
 validates through the BAF JWT validator, trusted replay service, NSS/SSSD
 identity binding and PAM before starting a session. Preserves the classic
 username/password PAM login. Ships the xrdp-baf-replayd and xrdp-baf-handled
 trusted services.
CTRL

# conffiles: don't clobber admin-edited config on upgrade
( cd "$STAGE" && find etc/xrdp -type f 2>/dev/null | sed 's,^,/,' ) \
    > "$STAGE/DEBIAN/conffiles"

cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
# xrdp must be able to start Xorg for a non-console user.
if [ ! -f /etc/X11/Xwrapper.config ] || \
   ! grep -q '^allowed_users=anybody' /etc/X11/Xwrapper.config 2>/dev/null; then
    printf 'allowed_users=anybody\nneeds_root_rights=yes\n' > /etc/X11/Xwrapper.config
fi
# Default the desktop to xfce when it is the installed session manager.
if [ -x /usr/bin/xfce4-session ]; then
    update-alternatives --set x-session-manager /usr/bin/xfce4-session \
        >/dev/null 2>&1 || true
fi
systemctl daemon-reload || true
systemctl enable xrdp-baf-replayd.service xrdp-baf-handled.service \
    >/dev/null 2>&1 || true
# BAF stays disabled until the admin sets [BrokerAuth] in sesman.ini.
echo "xrdp-baf installed. Configure [BrokerAuth] in /etc/xrdp/sesman.ini and"
echo "install a matching xorgxrdp-baf before enabling broker sessions."
exit 0
POST
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'PRE'
#!/bin/sh
set -e
systemctl disable --now xrdp-baf-replayd.service xrdp-baf-handled.service \
    >/dev/null 2>&1 || true
exit 0
PRE
chmod 0755 "$STAGE/DEBIAN/prerm"

dpkg-deb --root-owner-group --build "$STAGE" \
    "$OUT/xrdp-baf_${PKGVER}_${ARCH}.deb" >/dev/null
echo "  -> $OUT/xrdp-baf_${PKGVER}_${ARCH}.deb"

# --- 4. Matching xorgxrdp ------------------------------------------------
if [ "$SKIP_XORG" -eq 0 ]; then
    echo "== building xorgxrdp-baf ${PKGVER} =="
    XSRC="$OUT/xorgxrdp-src"
    git clone --depth 1 -b "${XORGXRDP_VERSION:-devel}" \
        https://github.com/neutrinolabs/xorgxrdp "$XSRC" >/dev/null 2>&1
    XSTAGE="$OUT/xorgxrdp-baf"
    ( cd "$XSRC"
      ./bootstrap >/dev/null
      # Build against the staged (not-yet-installed) xrdp devel files: sysroot
      # makes pkg-config resolve xrdp's Cflags into the stage tree.
      PKG_CONFIG_SYSROOT_DIR="$STAGE" \
      PKG_CONFIG_PATH="$STAGE/usr/lib/pkgconfig:$STAGE/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)/pkgconfig" \
        ./configure >/dev/null
      make -j"$(nproc)" >/dev/null
      make install DESTDIR="$XSTAGE" >/dev/null )
    install -d "$XSTAGE/DEBIAN"
    XDEPS="$(compute_deps "$XSTAGE" xorgxrdp-baf)"
    cat > "$XSTAGE/DEBIAN/control" <<CTRL
Package: xorgxrdp-baf
Version: ${PKGVER}
Architecture: ${ARCH}
Maintainer: XRDP BAF <xrdp-devel@googlegroups.com>
Depends: ${XDEPS:-libc6}, xserver-xorg-core
Provides: xorgxrdp
Conflicts: xorgxrdp
Replaces: xorgxrdp
Section: x11
Priority: optional
Description: Xorg drivers matching xrdp-baf (${VER})
 xorgxrdp video and input drivers built against xrdp-baf ${VER}. Required so
 the Xorg session publishes RandR outputs and the desktop renders; the distro
 xorgxrdp is ABI-incompatible with this xrdp and yields black sessions.
CTRL
    dpkg-deb --root-owner-group --build "$XSTAGE" \
        "$OUT/xorgxrdp-baf_${PKGVER}_${ARCH}.deb" >/dev/null
    echo "  -> $OUT/xorgxrdp-baf_${PKGVER}_${ARCH}.deb"
fi

echo "== done. Install with: apt install ./out/xrdp-baf_*.deb ./out/xorgxrdp-baf_*.deb =="
