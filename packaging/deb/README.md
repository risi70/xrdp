# Debian packages for xrdp-baf

Builds installable `.deb` packages of the broker-authenticated XRDP solution
for **Ubuntu 24.04 (noble)** and **26.04**.

> **Prebuilt (24.04):** don't want to build? Download checksummed packages from
> the release repository in [`dist/`](../../dist/) and skip to *Install*:
> ```bash
> BASE=https://raw.githubusercontent.com/risi70/xrdp/mvp-broker-assertion/dist
> wget "$BASE/xrdp-baf_0.10.80~baf1+noble_amd64.deb" \
>      "$BASE/xorgxrdp-baf_0.10.80~baf1+noble_amd64.deb" "$BASE/SHA256SUMS"
> sha256sum -c SHA256SUMS --ignore-missing
> ```

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

Runtime dependencies are computed from the built binaries (ldd every ELF, map
each shared object to its owning package with `dpkg -S`), so they resolve
correctly per release without needing a `debian/` tree.

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
## Smart card: two different things

- **Smart-card *login*** (card → broker → Mode C) is **always enabled** — it is
  `--enable-broker-auth` (in this package) plus the broker connector
  (`packaging/uds`). It needs nothing here.
- **In-session smart-card *redirection*** (MS-RDPESC, using the card inside the
  desktop) is now **built into the default package** (`--enable-smartcard`), per
  the deployment decision to support redirecting the IGEL OS card into the
  session. This is the upstream MS-RDPESC code, which upstream marks
  experimental (commit `7a2ac0c1`: the code *"contains a number of security
  vulnerabilities and does not work at the moment"*).

  We reviewed that code before turning it on; the findings — and their
  operational containment — are captured in an **internal MS-RDPESC security
  review** (held privately pending coordinated upstream disclosure; ask the
  maintainers). **Read it before exposing redirection to untrusted clients.**
  The redirected pcsc socket lives
  in the *user's own session* (`$HOME/.pcsc<display>`, dir mode 0700), so the
  parsing bugs are reachable only by the RDP client already bound to that
  session — a client attacking its own session — not by other local users.

  To build **without** redirection (recommended if you do not need in-session
  card use):
  ```bash
  WITH_SMARTCARD=0 packaging/deb/build-deb.sh
  ```
