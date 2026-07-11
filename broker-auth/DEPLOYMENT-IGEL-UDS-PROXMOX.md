# Deployment guide: IGEL OS 12 · UDS Enterprise · Ubuntu 24.04 · Proxmox VE

This guide installs the broker-authenticated XRDP solution (BAF + Mode C
ingress) on a production-style stack:

| Layer | Component | Role |
|---|---|---|
| Hypervisor | **Proxmox VE 8.x** | Hosts the broker and VDI virtual machines |
| Broker | **UDS Enterprise 4.x** (OpenUDS) | Authenticates users, manages desktop pools, issues the connection |
| VDI | **Ubuntu 24.04 LTS** | Runs the patched XRDP + BAF services; the actual Linux desktop |
| Endpoint | **IGEL OS 12** | Thin client; runs the UDS client and the RDP session |

## 1. How the pieces fit (read this first)

XRDP has **no server-side NLA/CredSSP**, so a smart card or password cannot
authenticate the RDP connection the way it does on Windows. Instead the
**broker authenticates the user** and hands the client a **single-use Mode C
handle** that rides standard RDP to the VDI:

```
IGEL OS 12  ──user auth──▶  UDS Enterprise ──validates cert/pwd/MFA──▶  identity
                                    │
                                    ├─ requests a BAF assertion for (user,target)
                                    ├─ registers it with the VDI handle service ─▶ one-time handle
                                    ▼
IGEL launches RDP to the Ubuntu VDI carrying the handle as either
  • an X.224 routing token   "Cookie: msts=<64-hex handle>"      (Mode C channel 1)
  • or the connection password (handle-shaped)                   (Mode C channel 2)
                                    ▼
Ubuntu VDI xrdp ── Mode C ingress ──▶ resolve handle ──▶ BAF validator
  ──▶ trusted replay ──▶ NSS/SSSD identity ──▶ UID0 reject ──▶ PAM ──▶ xfce session
```

The handle is a reference, never the assertion; the assertion stays
server-side. The full validation and PAM chain runs inside `xrdp-sesexec` on
the VDI — the broker never bypasses local Linux authority.

**Implementation status (be honest with yourself before deploying):**
- The VDI side (XRDP + BAF validator, replay service, handle service, Mode C
  routing-token and one-time-credential ingress, NSS/SSSD/PAM) is implemented
  and verified end to end.
- Smart-card → broker authentication is implemented in the **reference
  broker** (`broker-auth/reference-broker/`). Wiring it into UDS Enterprise's
  authenticator/transport is a **deployment integration task** (SD-009 C6,
  not yet shipped). Section 5 describes the integration points and gives a
  working reference path using the bundled broker components.

---

## 2. Prerequisites

- Proxmox VE 8.x cluster or single node with hardware virtualization.
- A UDS Enterprise 4.x appliance image (or OpenUDS), licensed as required.
- Network segments: management, a VDI network reachable by UDS and the
  endpoints, and (recommended) an isolated segment for the BAF services.
- DNS names for the UDS server and each VDI, and an NTP source (BAF
  assertions are time-bound; clock sync is mandatory).
- An identity source for UDS: AD/LDAP, SAML/OIDC IdP, or a smart-card CA.
- The XRDP+BAF source (this repository, branch `mvp-broker-assertion`).

---

## 3. Part A — Proxmox VE

1. **Create a VDI network.** In *Datacenter → SDN* or a Linux bridge
   (`vmbr1`), define the VDI subnet. Ensure UDS can reach the VDIs on TCP
   **3389** (RDP) and the VDIs can reach your NTP and identity services.

2. **Create an API token for UDS.** UDS's Proxmox provider clones and controls
   VMs via the API:
   - *Datacenter → Permissions → API Tokens*: create `uds@pve!uds` with
     privilege separation off (or a role granting `VM.Allocate`, `VM.Clone`,
     `VM.Config.*`, `VM.PowerMgmt`, `Datastore.AllocateSpace`).
   - Record the token secret.

3. **Build the Ubuntu 24.04 golden template** (VM ID e.g. `9000`):
   - Create a VM from the Ubuntu 24.04 LTS ISO or cloud image, `qemu-guest-agent`
     enabled, a single disk on shared/replicated storage.
   - Complete **Part B** inside this VM, then generalize it (truncate
     machine-id, remove SSH host keys) and convert it to a **template**.
   - UDS will linked-clone desktops from this template.

---

## 4. Part B — Ubuntu 24.04 VDI (build + configure)

Perform these steps in the golden template. All commands run as root.

### 4.1 Build and install XRDP with broker-auth

```bash
apt-get update
apt-get install -y build-essential autoconf automake libtool pkg-config \
    libssl-dev libpam0g-dev libx11-dev libxfixes-dev libxrandr-dev \
    libxkbfile-dev libpixman-1-dev libsm-dev libice-dev \
    libjwt-dev libjansson-dev nasm git

git clone https://github.com/risi70/xrdp.git /opt/xrdp-src
cd /opt/xrdp-src
git checkout mvp-broker-assertion
./bootstrap
./configure --enable-broker-auth --disable-rfxcodec
make -j"$(nproc)"
make install          # installs to /usr/local/sbin, config to /etc/xrdp
```

This installs `xrdp`, `xrdp-sesman`, `xrdp-sesexec`, and the BAF daemons
`xrdp-baf-replayd` and `xrdp-baf-handled`, plus `/usr/local/lib/pkgconfig/xrdp.pc`.

### 4.2 Build a matching xorgxrdp (required)

The distro `xorgxrdp` package (0.9.x) is **ABI-incompatible** with this XRDP
(0.10.x): the Xorg session starts but publishes no RandR outputs and the
desktop never renders. Build xorgxrdp against the XRDP you just installed:

```bash
apt-get install -y xserver-xorg-dev
git clone https://github.com/neutrinolabs/xorgxrdp /opt/xorgxrdp-src
cd /opt/xorgxrdp-src
./bootstrap
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure
make -j"$(nproc)"
make install
```

### 4.3 Desktop and session

```bash
apt-get install -y xfce4 dbus-x11
# Xorg started by xrdp for a non-console user must be allowed:
printf 'allowed_users=anybody\nneeds_root_rights=yes\n' > /etc/X11/Xwrapper.config
# Only xfce is installed, so make it the default session:
update-alternatives --set x-session-manager /usr/bin/xfce4-session
```

Users get a stable desktop via `~/.xsession` (`exec startxfce4`), provisioned
by your identity integration (or a skeleton in `/etc/skel`).

### 4.4 Linux identity (NSS/SSSD) and PAM

BAF binds the broker identity to a **real Linux account** — it never trusts
token UID/GID. Join the VDI to your directory so broker usernames resolve:

```bash
apt-get install -y sssd sssd-tools realmd adcli
realm join --user=<admin> ad.example.com      # or configure sssd.conf for LDAP
```

PAM account and session stacks (`/etc/pam.d/xrdp-sesman`) must approve the
user; the default `common-account`/`common-session` via SSSD is sufficient.
Ensure `getent passwd <brokeruser>` resolves before continuing.

### 4.5 BAF trusted services and configuration

```bash
install -d -m 0755 /etc/xrdp/baf /run/xrdp-baf
# Install your production trust anchor (broker's public signing key / JWKS):
cp broker-signing-key.pub /etc/xrdp/baf/trust-anchor.pem
```

systemd units for the replay and handle services:

```ini
# /etc/systemd/system/xrdp-baf-replayd.service
[Unit]
Description=XRDP BAF trusted replay service
After=network.target
[Service]
ExecStart=/usr/local/sbin/xrdp-baf-replayd -s /run/xrdp-baf/replay.sock
Restart=on-failure
RuntimeDirectory=xrdp-baf
[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/xrdp-baf-handled.service
[Unit]
Description=XRDP BAF one-time handle service
After=network.target
[Service]
ExecStart=/usr/local/sbin/xrdp-baf-handled -s /run/xrdp-baf/handle.sock
Restart=on-failure
RuntimeDirectory=xrdp-baf
[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now xrdp-baf-replayd xrdp-baf-handled
```

Configure the trusted `[BrokerAuth]` section of `/etc/xrdp/sesman.ini`
(these values are read only from this local file, never from the client):

```ini
[BrokerAuth]
BrokerAuthEnabled=true
RDSAADEnabled=false
Provider=jwt
Issuer=https://uds.example.com/baf            ; must match the assertion iss
KeyId=baf-key-1                                ; must match the JWS kid
AllowedAlgorithms=RS256
TrustAnchor=/etc/xrdp/baf/trust-anchor.pem
ExpectedAudience=xrdp://ubuntu-vdi             ; must match aud
LocalTarget=urn:baf:desktop:pool:ubuntu-vdi    ; must match target
MaxAssertionSize=16384
ReplayBackend=service
ReplaySocket=/run/xrdp-baf/replay.sock
RejectUid0=true
AllowSessionStart=true                         ; gate: false until validated
ModeCOneTimeCredential=true                    ; enable handle-as-password
HandleSocket=/run/xrdp-baf/handle.sock
RequireNonceBinding=false                      ; true only with nonce-capable ingress
```

Enable the routing-token channel in `/etc/xrdp/xrdp.ini` `[Globals]`:

```ini
broker_auth_enabled=true
broker_auth_modec_ingress_enabled=true
```

Restart and verify:

```bash
systemctl restart xrdp xrdp-sesman
xrdp-sesman --dump-config | sed -n '/BrokerAuth/,/^$/p'   # confirms parsing
```

---

## 5. Part C — UDS Enterprise (broker)

Install the UDS server + tunnel appliance on Proxmox (import the OVA/image, or
deploy OpenUDS). Then, in the UDS admin UI:

1. **Proxmox provider** — *Services → New → Proxmox Platform Provider*: point
   at the Proxmox API with the `uds@pve!uds` token; select the Ubuntu 24.04
   template (`9000`) as a linked-clone service.

2. **Authenticator** — *Authenticators*: add your identity source (AD/LDAP,
   SAML, or a **certificate authenticator** for smart cards). The username UDS
   authenticates must equal the Linux/SSSD username on the VDI.

3. **OS Manager** — Linux OS Manager, "remove on logout" or "keep" as policy.

4. **Service Pool** — bind the provider service + OS manager; set assignment.

5. **RDP transport** — *Transports → New → RDP*. This is where the Mode C
   handle is injected:
   - The transport builds the `.rdp` / client parameters for the endpoint.
   - **Routing-token channel:** set the load-balance/routing cookie to
     `Cookie: msts=<handle>`.
   - **One-time-credential channel:** set the RDP password field to `<handle>`
     and the username to the broker-designated user.

### 5.1 Producing the BAF handle (the integration point)

UDS must, per connection, obtain a BAF assertion and register it with the
VDI's handle service to get the single-use handle. Two options:

- **Reference path (available now):** run the bundled broker components on the
  UDS host as a small sidecar the RDP transport calls:
  ```bash
  # on the UDS host, per connection:
  python3 broker-auth/reference-broker/smartcard_login.py \
      --p12 <user-cert.p12> --pin <pin> --ca /etc/uds/baf/ca.pem \
      --issuer-key /etc/uds/baf/issuer.key --issuer https://uds.example.com/baf \
      --audience xrdp://ubuntu-vdi --target urn:baf:desktop:pool:ubuntu-vdi \
      --kid baf-key-1 > assertion.jwt
  # register with the target VDI's handle service (over a trusted mTLS/root path):
  HANDLE=$(baf_handle_tool store -s <vdi-handle-socket> \
      -t urn:baf:desktop:pool:ubuntu-vdi -l 90 < assertion.jwt)
  # inject $HANDLE into the RDP transport parameters
  ```
  For password/MFA (non-smart-card) auth, replace `smartcard_login.py` with a
  direct assertion mint (`reference-broker/issue_assertion.py`) after UDS has
  authenticated the user.

- **Production path (to implement — SD-009 C6):** a UDS transport plugin that
  performs the mint+register in-process and reaches the VDI handle service
  over a root-owned socket (co-located) or mutually-authenticated TLS (remote).
  This removes the sidecar and is the recommended long-term integration.

The broker's signing key must correspond to the VDI's `TrustAnchor`, and its
`issuer/audience/target/kid` must match the VDI `[BrokerAuth]` values exactly.

---

## 6. Part D — IGEL OS 12 (endpoint)

1. **Register** the device with IGEL UMS and apply your profile.
2. **UDS client:** deploy the UDS Connector for Linux via a **Custom Partition**
   (IGEL's app-container mechanism), or use the UDS **HTML5/RDP** path where a
   custom client is undesirable. IGEL OS 12 ships a FreeRDP-based RDP client
   that honors the routing token / credential parameters UDS provides.
3. **Flow:** the user authenticates to the UDS portal (password/MFA or smart
   card via the IGEL smart-card reader). UDS assigns a desktop, produces the
   handle (Section 5.1), and launches the IGEL RDP session with the handle in
   the routing token or password field. No custom RDP plugin is required on
   the endpoint, and the assertion never touches the endpoint.

---

## 7. End-to-end verification

On the VDI, tail the logs while a user connects from IGEL:

```bash
journalctl -u xrdp -u xrdp-sesman -f
```

A successful Mode C login shows:

```
Captured Mode C broker handle from X.224 routing token       # (routing-token channel)
Received request from ... to create a session for user <u>   # BAF chain authorized
Starting X server on display X11-10: Xorg :10 ...            # xorgxrdp session
Session ... is now running                                   # xfce desktop
```

If the desktop is black, re-check Part B §4.2 (matching xorgxrdp) and §4.3
(Xwrapper + xfce session). If auth fails closed, verify clock sync, the
`Issuer/Audience/Target/KeyId/TrustAnchor` all match between broker and VDI,
and that the replay and handle services are running.

The repository's lab harness reproduces the VDI-side chain headlessly and on a
KVM VM (`test-lab/phase6/modec-smoke/`), including the smart-card and SoftHSM2
lifecycle tests — use it to validate a VDI image before templating.

---

## 8. Security hardening

- **Clocks:** enforce NTP/chrony on broker and VDIs; assertions are ≤300 s and
  replay entries expire on `exp + skew`.
- **Handle service reachability:** the VDI handle service must be reachable
  only by the broker — root-owned UNIX socket if co-located, otherwise mTLS
  with a pinned broker certificate and network segmentation.
- **Signing keys:** protect the broker signing key with an HSM/KMS; rotate with
  overlapping `kid`s; publish trust anchors to VDIs out of band.
- **Never log** raw assertions, handles, PINs, or private keys. Log only
  broker session id, target, and result class.
- **UID 0 rejection** stays on; token groups are never treated as Unix groups.
- **`AllowSessionStart`** stays false on a VDI image until its trusted config
  is validated in place.
- Keep the endpoint credential-field usage (Mode C channel 2) off if policy
  forbids credentials in the RDP password field; prefer the routing-token
  channel.

---

## 9. Known limitations

- **No server-side NLA** in XRDP: smart cards authenticate to the broker, not
  the RDP connection (by design here).
- **UDS↔BAF transport plugin (C6)** is not yet productized; Section 5.1's
  reference sidecar is the current integration path.
- **Clustered/HA replay:** the handle and replay services are host-local. For
  a desktop pool, either bind assertions to a specific target (so a handle
  cannot move hosts) or deploy a shared atomic replay store.
- Validate a matching **xorgxrdp** whenever XRDP is upgraded; an ABI mismatch
  silently yields black desktops.
