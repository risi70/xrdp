# Debian XRDP BAF Package

`build-deb.sh` creates a staged `xrdp-baf` package from tracked files in the
current Git commit. The build enables the BAF compile gate, runs the focused
BAF tests, and installs disabled-by-default replay and Handle service units.

The package does not contain untracked files, private broker material,
Keycloak tokens, signing keys, cached binaries, a production broker, or a
production UDS integration.

## Build dependencies

```sh
sudo apt-get install build-essential autoconf automake libtool pkg-config \
    dpkg-dev binutils tar libssl-dev libpam0g-dev libx11-dev \
    libxfixes-dev libxrandr-dev libxkbfile-dev libpixman-1-dev libsm-dev \
    libice-dev libjwt-dev libjansson-dev nasm
```

Keep this dependency list in sync with the copy in
`broker-auth/DEPLOYMENT-KEYCLOAK-BAF-XRDP.md`.

## Build

```sh
packaging/deb/build-deb.sh
```

Output is written to `packaging/deb/out/`, with a SHA-256 checksum and a text
manifest beside the package. Build on the target Debian or Ubuntu release so
the generated shared-library dependencies match that release.

Upstream's install target creates TLS and legacy RSA credentials. The package
builder removes those generated files, rejects any remaining private-key
markers, and the package creates fresh host-local credentials during
installation. No build-time private key is distributed.

Install `xorgxrdp` from the target distribution separately. This workflow does
not fetch or package external source code.

## Activation

Installing the package does not enable BrokerAuth, `xrdp-baf-replayd`, or
`xrdp-baf-handled`. Follow
`broker-auth/DEPLOYMENT-KEYCLOAK-BAF-XRDP.md` and enable only the services used
by the selected ingress.
