# Binary artifacts (BAF release repository)

Prebuilt, installable artifacts for the broker-authenticated XRDP (BAF)
solution, so an operator can deploy without building from source. Each file is
downloadable by raw URL (see below) and covered by `SHA256SUMS`.

> These are built for **Ubuntu 24.04 (noble)**. `.deb` packages are
> release-specific — for 26.04 build with `packaging/deb/build-deb.sh` on 26.04.
> The `xrdp-baf` package is built with in-session smart-card redirection
> enabled (`--enable-smartcard`); read the internal MS-RDPESC security review
> (held privately pending coordinated upstream disclosure) first.

## Artifacts

| File | What it is |
|---|---|
| `xrdp-baf_0.10.80~baf1+noble_amd64.deb` | Patched XRDP + BAF validator/replay/handle services (`Provides/Conflicts/Replaces: xrdp`). Smart-card redirection built in. |
| `xorgxrdp-baf_0.10.80~baf1+noble_amd64.deb` | Xorg drivers matching this XRDP (`Provides/Conflicts/Replaces: xorgxrdp`). Required — the distro 0.9.x is ABI-incompatible and yields black sessions. |
| `baf-uds-connector_0.10.80~baf1.tar.gz` | Self-contained UDS Enterprise / OpenUDS connector installer (`baf-uds-connect` + broker components). Extract and run `packaging/uds/install.sh`. |
| `SHA256SUMS` | Checksums for the three artifacts above. |

## Download URLs

Base: `https://raw.githubusercontent.com/risi70/xrdp/mvp-broker-assertion/dist/`

```bash
BASE=https://raw.githubusercontent.com/risi70/xrdp/mvp-broker-assertion/dist
wget "$BASE/xrdp-baf_0.10.80~baf1+noble_amd64.deb"
wget "$BASE/xorgxrdp-baf_0.10.80~baf1+noble_amd64.deb"
wget "$BASE/baf-uds-connector_0.10.80~baf1.tar.gz"
wget "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS      # verify integrity before installing
```

## Install

**VDI (Ubuntu 24.04):**
```bash
sudo apt install ./xrdp-baf_0.10.80~baf1+noble_amd64.deb \
                 ./xorgxrdp-baf_0.10.80~baf1+noble_amd64.deb
```

**UDS host:**
```bash
tar xzf baf-uds-connector_0.10.80~baf1.tar.gz
sudo baf-uds-connector/packaging/uds/install.sh
```

Full walkthrough: [`../broker-auth/DEPLOYMENT-IGEL-UDS-PROXMOX.md`](../broker-auth/DEPLOYMENT-IGEL-UDS-PROXMOX.md).

## Notes / provenance

- Rebuild these from source with `packaging/deb/build-deb.sh` (debs) and
  `dist/make-dist.sh` (this whole directory). The tarball is just the
  `packaging/uds` + `broker-auth` files `install.sh` needs, in repo layout, so
  it runs unmodified after extraction.
- The raw URLs track the **`mvp-broker-assertion` branch** and change when the
  branch is updated; for an immutable link, substitute a commit SHA or tag for
  the branch name. If these binaries are later moved to **GitHub Releases**,
  update the base URL here and in the deployment guide accordingly.
- Binaries are committed to the repo by request; this bloats git history. If
  that becomes a problem, migrate `dist/` to GitHub Releases (release assets get
  their own stable download URLs) and keep only this README as the pointer.
