# Debian packages for xrdp-baf

Builds installable `.deb` packages of the broker-authenticated XRDP solution
for **Ubuntu 24.04 (noble)** and **26.04**.

## Build

Packages are release-specific — build on the target release (build on 24.04
for 24.04, on 26.04 for 26.04):

```bash
sudo apt-get install build-essential autoconf automake libtool pkg-config \
  libssl-dev libpam0g-dev libx11-dev libxfixes-dev libxrandr-dev \
  libxkbfile-dev libpixman-1-dev libsm-dev libice-dev libjwt-dev \
  libjansson-dev nasm git xserver-xorg-dev dpkg-dev rsync

packaging/deb/build-deb.sh            # or --skip-xorgxrdp
```

Outputs to `packaging/deb/out/`:

| Package | Contents |
|---|---|
| `xrdp-baf_<ver>~baf1+<codename>_<arch>.deb` | Patched XRDP + BAF validator/replay/handle services (`Provides/Conflicts/Replaces: xrdp`) |
| `xorgxrdp-baf_..._<arch>.deb` | Xorg drivers built to match this XRDP (`Provides/Conflicts/Replaces: xorgxrdp`) |

Runtime dependencies are computed from the built binaries with
`dpkg-shlibdeps`, so they resolve correctly per release.

## Install (on the VDI)

```bash
sudo apt install ./xrdp-baf_*.deb ./xorgxrdp-baf_*.deb
```

The `xorgxrdp-baf` package is required: the distro `xorgxrdp` (0.9.x) is
ABI-incompatible with this XRDP (0.10.x) and yields black sessions. The
`postinst` sets `Xwrapper.config` (so xrdp can start Xorg for a non-console
user), defaults the desktop to xfce4 when present, and enables the BAF
replay/handle services. **BAF stays inactive until you configure
`[BrokerAuth]` in `/etc/xrdp/sesman.ini`** (see the deployment guide,
`broker-auth/DEPLOYMENT-IGEL-UDS-PROXMOX.md` §4.5).

Config files under `/etc/xrdp` are registered conffiles, so admin edits
survive upgrades.

## Notes

- These are pragmatic staged packages (`dpkg-deb`), suitable for building a
  controlled VDI image or a private apt repo. For archive-quality packaging,
  wrap the autotools build in `debian/` + `dpkg-buildpackage`.
- `xorgxrdp` tracks `neutrinolabs/xorgxrdp` `devel` by default; pin with
  `XORGXRDP_VERSION=<tag>` if you need a specific revision.
- To add smart-card *redirection* into sessions, rebuild with
  `--enable-smartcard` (see deployment guide Appendix A) — it is off in these
  packages because upstream marks it experimental.
