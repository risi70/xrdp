# Deploying Keycloak, a BAF Broker, and XRDP

This guide describes the supported integration boundary for the experimental
Broker Authentication Framework (BAF) extension. Keycloak authenticates the
user. A trusted broker validates the Keycloak access token and issues a
separate, short-lived BAF assertion. XRDP validates only the BAF assertion.

The implementation is build-gated and disabled by default. Do not enable it
until the broker, trust anchor, replay service, Linux account resolution, and
PAM policy have all been configured and tested.

## Security boundary

- Use Authorization Code with PKCE at the user-facing client. Do not use the
  Resource Owner Password Credentials grant.
- Deliver Keycloak tokens to the broker over a protected channel. Never put a
  token or BAF assertion in a command line, URL, log, username, password, or
  RDP routing token.
- The broker validates the Keycloak issuer, signature algorithm, signature,
  audience, authorized party, token type, time claims, and client-scoped
  desktop role before issuing a broker-neutral assertion.
- XRDP trusts the broker's BAF signing key, not the Keycloak signing key.
- Linux users must already resolve through system NSS. XRDP does not provision
  accounts and does not trust UID, GID, home, shell, or Unix groups from token
  claims.
- PAM account and session policy remains authoritative. Broker authentication
  does not call `pam_authenticate()` and does not change classic password/PAM
  login behavior.
- UID 0 is rejected by default.

The reference broker and UDS adapter are conformance and integration examples,
not a production identity front end or a production OpenUDS plugin.

## 1. Build the Debian package

Build on the same Debian or Ubuntu release used by the target desktop:

```sh
sudo apt-get install build-essential autoconf automake libtool pkg-config \
    dpkg-dev binutils tar libssl-dev libpam0g-dev libx11-dev \
    libxfixes-dev libxrandr-dev libxkbfile-dev libpixman-1-dev libsm-dev \
    libice-dev libjwt-dev libjansson-dev nasm
packaging/deb/build-deb.sh
```

Keep this dependency list in sync with the copy in `packaging/deb/README.md`.

The build stages tracked files from the current Git commit and verifies the
focused BAF test suite before producing `packaging/deb/out/xrdp-baf_*.deb`.
Untracked lab files, private material, caches, and previous artifacts cannot
enter the package.

Install the matching distro `xorgxrdp` package separately. The package built by
this repository contains XRDP and the BAF services; it does not build or bundle
an external xorgxrdp source tree.

## 2. Install XRDP

```sh
sudo apt install xorgxrdp
sudo apt install ./packaging/deb/out/xrdp-baf_*.deb
```

The package conflicts with the distribution `xrdp` package and preserves files
under `/etc/xrdp` as conffiles. It installs these disabled services:

- `xrdp-baf-replayd.service`: required trusted replay backend;
- `xrdp-baf-handled.service`: Broker-RDP Handle registration and resolution.

Neither service is enabled automatically. BAF also remains disabled in
`xrdp.ini` and `sesman.ini`.

Installation creates the system group `xrdp` if it does not exist and
generates host-local `/etc/xrdp/rsakeys.ini` plus a self-signed
`key.pem`/`cert.pem` pair when missing. Replace the self-signed TLS
certificate before production use.

## 3. Configure Keycloak and the broker

Create a dedicated confidential or otherwise appropriately protected client
for the broker API. Configure an explicit access-token audience and a
client-scoped desktop role. The reference adapter's illustrative settings are
in `broker-auth/reference-broker/config.example.yaml`.

At minimum, configure the broker with:

- the exact HTTPS Keycloak issuer URL;
- the expected access-token audience and authorized party (`azp`);
- the allowed asymmetric signing algorithms;
- the required client role;
- the BAF issuer, audience, key ID, signing key, target policy, and maximum
  assertion lifetime;
- an issuer-bound subject-to-local-user mapping and a per-user target
  allowlist.

Keep the BAF private signing key on the broker. Copy only its public trust
anchor to the XRDP host. A Keycloak access token must never be accepted as a
BAF assertion. The complete key and certificate inventory for the chain,
including the mutual-TLS and SSH material used by the `integrations/`
components, is listed in `DEPLOYMENT-PKI-CREDENTIALS.md`.

## 4. Configure trusted XRDP services

The package uses the compiled defaults:

```text
/run/xrdp/baf-replay.sock
/run/xrdp/baf-handle.sock
```

Start the replay service for every live broker-auth deployment. Start the
Handle service only when testing or deploying the Broker-RDP Handle ingress:

```sh
sudo systemctl enable --now xrdp-baf-replayd.service
sudo systemctl enable --now xrdp-baf-handled.service
```

Do not use the process-local replay backend for live activation. Restrict
access to the Handle socket to a trusted co-located broker component or a
separately authenticated, protected forwarding service.

## 5. Configure sesman

Use `broker-auth/BAF-RUNTIME-CONFIG.md` as the field reference. A Handle ingress
configuration has this shape; replace every example identifier and path with
deployment values:

```ini
[BrokerAuth]
BrokerAuthEnabled=true
RDSAADEnabled=false
AllowSessionStart=true
Issuer=https://broker.example.invalid/baf
KeyId=baf-signing-key-01
TrustAnchor=/etc/xrdp/baf-broker-public.pem
ExpectedAudience=xrdp-desktop
LocalTarget=desktop-01
ReplayBackend=service
ReplaySocket=/run/xrdp/baf-replay.sock
ModeCOneTimeCredential=true
HandleSocket=/run/xrdp/baf-handle.sock
```

`RDSAADEnabled` gates the native pre-MCS RDSAAD bridge and stays `false`
for the Handle ingress shown here. When both `BrokerAuthEnabled` and
`RDSAADEnabled` are true, `TrustAnchor`, `ExpectedAudience`, `LocalTarget`,
and `ReplaySocket` are mandatory.

The trust anchor must be root-owned and not writable by the XRDP service
account. Missing, ambiguous, or malformed configuration fails closed.

For the routing-token Handle channel, also set these fields in `xrdp.ini`:

```ini
[Globals]
broker_auth_enabled=true
broker_auth_modec_ingress_enabled=true
```

The one-time-credential Handle channel does not require putting an assertion in
the username or password. The password-shaped field carries only a random,
single-use server-side reference. The SD-008 versus proposed SD-009 ingress
selection remains unresolved; do not treat this guide as selecting between
them.

## 6. Prepare Linux identity and PAM

For every mapped user, verify system NSS resolution and a non-root UID:

```sh
getent passwd example-user
id example-user
```

Review `/etc/pam.d/xrdp-sesman` for account, credential, and session policy.
Broker auth still requires PAM account approval and the normal required
session/credential lifecycle. LDAP synchronization, SSSD, Active Directory,
Kerberos, domain join, and Microsoft Entra are optional site concerns, not BAF
requirements.

## 7. Reference UDS integration artifact

Build the sanitized reference installer from the current commit:

```sh
packaging/uds/build-installer.sh
```

The resulting tarball contains `install.sh`, `baf-uds-register`, and the
broker-neutral Handle protocol client. It accepts an already issued BAF
assertion only on a file descriptor, registers it with the trusted Handle
service, and returns a one-time handle. It does not authenticate users,
validate Keycloak tokens, issue assertions, hold a signing key, or implement a
production OpenUDS transport plugin.

A production-grade OpenUDS / UDS Enterprise transport plugin with a
multilingual portal experience is available separately in
`integrations/openuds-baf/`; the matching broker-side issuance service (the
broker-to-XRDP connector) is in `integrations/baf-broker-service/`.

## 8. Verification

Before enabling production traffic:

```sh
sudo apt-get install python3-pytest
make -C tests/baf check
PYTHONPATH=broker-auth python3 -m pytest broker-auth/tests \
    broker-auth/gateway/tests broker-auth/reference-broker/tests
systemctl is-active xrdp-baf-replayd.service
systemctl is-active xrdp-baf-handled.service
```

Test at least malformed input, wrong issuer/audience/target, expired assertion,
replay, unavailable replay/Handle service, unknown NSS user, UID 0, PAM account
denial, and incomplete configuration. Confirm classic username/password PAM
login still works. An Authentication Result `S_OK` is valid only after full
authorization and session readiness.

## Operational requirements

- Synchronize host clocks with chrony, systemd-timesyncd, or equivalent.
- Rotate Keycloak and BAF keys independently and pin allowed algorithms.
- Forward audit events without raw tokens, assertions, handles, or signing
  material.
- Treat replay or Handle service unavailability as an authentication outage,
  not a reason to bypass validation.
- Disable BrokerAuth and the two BAF services to roll back to classic XRDP
  password/PAM login.
