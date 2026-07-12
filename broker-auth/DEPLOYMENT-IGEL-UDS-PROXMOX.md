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

### 4.1 Install XRDP-BAF from the `.deb` packages

Deploy the two BAF packages (`xrdp-baf` + the matching `xorgxrdp-baf`) rather
than building from source on the golden template. Two options:

**Option A — build the `.deb` once, install everywhere (recommended).** On a
build host running the *same* Ubuntu release as the VDI (packages are
release-specific: build on 24.04 for a 24.04 image, on 26.04 for 26.04):

```bash
apt-get install -y build-essential autoconf automake libtool pkg-config \
    libssl-dev libpam0g-dev libx11-dev libxfixes-dev libxrandr-dev \
    libxkbfile-dev libpixman-1-dev libsm-dev libice-dev libjwt-dev \
    libjansson-dev nasm git xserver-xorg-dev dpkg-dev rsync

git clone https://github.com/risi70/xrdp.git /opt/xrdp-src
cd /opt/xrdp-src && git checkout mvp-broker-assertion
packaging/deb/build-deb.sh        # -> packaging/deb/out/*.deb  (see packaging/deb/README.md)
```

This produces `xrdp-baf_<ver>~baf1+<codename>_<arch>.deb` and the matching
`xorgxrdp-baf_..._<arch>.deb`. The `xrdp-baf` package is built with in-session
**smart-card redirection on by default** (`--enable-smartcard`); if you do not
need in-session card use, build with `WITH_SMARTCARD=0 packaging/deb/build-deb.sh`
(read `broker-auth/UPSTREAM-MS-RDPESC-REVIEW.md` first — that code is upstream-
experimental and we reviewed it before enabling it).

Copy both `.deb`s into the golden template and install:

```bash
apt-get update
apt-get install -y ./xrdp-baf_*.deb ./xorgxrdp-baf_*.deb
```

**Option B — build directly in the template.** Run the `build-deb.sh` block
above inside the template itself, then `apt-get install -y ./packaging/deb/out/*.deb`.

The install lays down `xrdp`, `xrdp-sesman`, `xrdp-sesexec`, the BAF daemons
`xrdp-baf-replayd`/`xrdp-baf-handled` (to `/usr/sbin`), and the matching Xorg
drivers. The package `Provides/Conflicts/Replaces: xrdp`, so it cleanly
supersedes any distro `xrdp`. Its `postinst` also does the desktop plumbing for
you (see §4.3).

### 4.2 Matching xorgxrdp — handled by the package

The distro `xorgxrdp` (0.9.x) is **ABI-incompatible** with this XRDP (0.10.x):
the Xorg session starts but publishes no RandR outputs and the desktop never
renders (upstream issue #3249). The `xorgxrdp-baf` package you installed in §4.1
is built against this exact XRDP and `Provides/Conflicts/Replaces: xorgxrdp`, so
it supersedes the distro driver. **Do not install the distro `xorgxrdp`** — no
separate manual build is needed.

### 4.3 Desktop and session

```bash
apt-get install -y xfce4 dbus-x11
```

The `xrdp-baf` `postinst` already writes `/etc/X11/Xwrapper.config`
(`allowed_users=anybody`, so xrdp can start Xorg for a non-console user) and,
when `xfce4-session` is present, sets it as the default `x-session-manager` — so
install xfce4 **before** the package if you can, or re-run
`update-alternatives --set x-session-manager /usr/bin/xfce4-session` afterwards.

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
install -d -m 0755 /etc/xrdp/baf
# Install your production trust anchor (broker's public signing key / JWKS):
cp broker-signing-key.pub /etc/xrdp/baf/trust-anchor.pem
```

The replay and handle services ship **with the package** (units in
`/lib/systemd/system/xrdp-baf-replayd.service` and `…-handled.service`, running
`/usr/sbin/xrdp-baf-{replayd,handled}` with a systemd `RuntimeDirectory=xrdp-baf`,
so `/run/xrdp-baf` is created automatically). The `postinst` already ran
`systemctl enable` on both; just start them:

```bash
systemctl start xrdp-baf-replayd xrdp-baf-handled
systemctl status xrdp-baf-replayd xrdp-baf-handled --no-pager   # confirm active
```

They stay dormant with respect to auth until you turn on `[BrokerAuth]` below —
enabling the package does **not** change behaviour for existing
username/password xrdp users.

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
VDI's handle service to get the single-use handle. Install the **BAF UDS
connector** on the UDS host (self-contained venv + the broker components + the
`baf-uds-connect` CLI the transport calls; see `packaging/uds/README.md`):

```bash
# on the UDS host, from a checkout of the xrdp repo:
sudo packaging/uds/install.sh
#   -> /opt/baf-uds (venv + components), /usr/local/bin/baf-uds-connect,
#      /etc/baf-uds/config.yaml
```

Edit `/etc/baf-uds/config.yaml` so `issuer / audience / target / kid` **exactly
match** the VDI `[BrokerAuth]` values (§4.5), place the broker signing key
(RS256 private PEM — its public half is the VDI `TrustAnchor`) at the
configured `issuer_key`, and for smart-card auth place the CA at `ca`.

Then have the UDS RDP transport call the CLI per connection, after UDS has
authenticated the user:

```bash
# routing-token channel (password/MFA/SAML user UDS already authenticated):
baf-uds-connect --user "$USERNAME" --format cookie
#   -> Cookie: msts=<64-hex handle>     (set as the RDP loadbalanceinfo/cookie)

# one-time-credential channel:
HANDLE=$(baf-uds-connect --user "$USERNAME")
#   -> set the RDP password field to $HANDLE, username to $USERNAME

# smart-card auth (the card authenticates to the broker first):
baf-uds-connect --smartcard --p12 <user.p12> --pin "$PIN" --format cookie
```

The connector mints the assertion, registers it with the target VDI's handle
service via the wire-compatible `baf_handle_client.py`, and returns the handle.
For reaching a **remote** VDI handle socket, see `packaging/uds/README.md`
("Reaching the VDI handle service" — forwarded socket now; the SD-009 **C6**
mTLS bridge is the productization). A native in-process UDS transport plugin is
the long-term integration that removes the CLI hop.

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
- **UDS↔BAF transport plugin (C6)** is not yet productized; the §5.1
  `baf-uds-connect` connector is the current integration path.
- **Clustered/HA replay:** the handle and replay services are host-local. For
  a desktop pool, either bind assertions to a specific target (so a handle
  cannot move hosts) or deploy a shared atomic replay store.
- Validate a matching **xorgxrdp** whenever XRDP is upgraded; an ABI mismatch
  silently yields black desktops.

---

## Appendix A — Optional: in-session smart-card redirection

This is **separate from and independent of** the Mode C broker login. Mode C
uses the card to authenticate you to the broker and get the session; this
appendix makes the **same physical card usable *inside* the desktop session**
(sign email, PKI web auth, `ssh -I`, GnuPG) via standard RDP smart-card
redirection ([MS-RDPESC]). Enable it only if you need in-session card use.

### A.0 Status — read before enabling

- XRDP implements the **server counterpart to MS-RDPESC**: `sesman/chansrv/`
  handles the full SCARD IOCTL set (`ESTABLISH_CONTEXT`, `CONNECT_*`,
  `BEGIN/END_TRANSACTION`, `GET_STATUS_CHANGE_*`, `LIST_READERS`, `GETATTRIB`,
  `TRANSMIT`, …) over `rdpdr` and re-exposes the card to session apps through a
  `libpcsclite`-compatible socket.
- This is `--enable-smartcard`, which upstream marks **"experimental — not for
  production."** The `xrdp-baf` `.deb` from §4.1 is **built with it on by
  default** (per the IGEL card-redirection deployment decision), so on a
  package install the server side is already present — there is nothing to
  rebuild. Treat the path as *supported-but-unvalidated*: interop-test it
  against your specific MS RD Core SDK client build before relying on it. It
  does **not** require NLA (redirection runs on the post-connection `rdpdr`
  channel).
- **Read `broker-auth/UPSTREAM-MS-RDPESC-REVIEW.md` first.** We reviewed this
  upstream code before enabling it: the return-path parsers trust
  client-supplied lengths without bounds checks (OOB read/write reachable by
  the RDP client bound to the session). The redirected pcsc socket is `0700`
  under the session `$HOME`, so the exposure is confined to that user's own
  session (crash/DoS + memory disclosure into its own pcsc response), not a
  cross-user host compromise — but it is a real reason to restrict redirection
  to managed endpoints. To build **without** redirection, use
  `WITH_SMARTCARD=0 packaging/deb/build-deb.sh` and install that package.

### A.1 Server (Ubuntu VDI): already present in the package

No rebuild is needed — the `xrdp-baf` package installed in §4.1 already carries
`--enable-smartcard`. (To confirm: `strings /usr/sbin/xrdp-chansrv | grep -qi
scard` succeeds on a redirection-enabled build.)

`xrdp-chansrv` advertises the redirected smart-card device and, when a
client redirects a card, creates a PC/SC IPC endpoint at
**`$HOME/.pcsc<display>/`** in the session (e.g. `~/.pcsc10.0`). XRDP ships a
drop-in `libpcsclite` wrapper (`sesman/chansrv/pcsc/`) that points pcsc-lite
clients at that endpoint instead of a local `pcscd`.

### A.2 Client (IGEL OS 12 / RD Core): redirect at the PC/SC layer

In the IGEL RDP session profile, enable **smart-card (PC/SC) redirection** —
the "Windows way" ([MS-RDPESC]). **Do not** use raw USB device redirection of
the reader: USB passthrough hands the reader exclusively to the session and
removes it from the endpoint, whereas PC/SC redirection is shareable (see A.4).
For a FreeRDP-based validation client the equivalent is `/smartcard` (not
`/usb:id,...`).

### A.3 In-session app wiring (Ubuntu VDI)

Session apps must use pcsc-lite and reach the redirected socket via the XRDP
wrapper rather than the system `libpcsclite`:

- Install/point the wrapper `libpcsclite.so` ahead of the system one for the
  session (e.g. in `~/.xsession` before `startxfce4`, prepend its directory to
  `LD_LIBRARY_PATH`). Do **not** run a local `pcscd` in the session — it would
  compete with the redirected endpoint.
- Point PKCS#11 apps at your card's module (e.g. `opensc-pkcs11.so`):
  - Firefox/Chromium: add the PKCS#11 module in the security-devices UI or via
    `modutil`/policy so the browser sees the redirected reader.
  - `ssh -I /usr/lib/.../opensc-pkcs11.so`, GnuPG scdaemon, `pkcs11-tool
    --module ...` all work once the wrapper resolves to the redirected card.
- Verify inside the session: `pkcs11-tool --list-slots` (or `pcsc_scan`) should
  show the client's reader/card.

### A.4 Does the card stay available to local IGEL browser apps? — Yes.

Because MS-RDPESC redirects at the **PC/SC / smart-card-service** layer (not the
USB device), the IGEL-local `pcscd` keeps ownership of the physical reader and
serves local apps concurrently in **shared mode** (`SCARD_SHARE_SHARED`). This
is the normal "smart-card SSO to the portal in the local browser *and* into the
session" pattern and it works. Caveats are **contention, not availability**:

- `BEGIN/END_TRANSACTION` take brief exclusive locks; a long transaction on
  either side blocks the other momentarily.
- If either side opens the card `SCARD_SHARE_EXCLUSIVE` (some PKI middleware
  does), the other is locked out until release.
- A few single-application applets serialize poorly under concurrent use.

Raw USB reader passthrough (A.2) is the only mode that would remove local
availability — avoid it if you need concurrent local browser access.

### A.5 Security trade-off

Redirecting the card into the session means the VDI host — and whoever
controls it — can drive PIN-verified operations on the card while it is
inserted. For high-assurance deployments consider **card-for-broker-login
only** (the base Mode C model, no redirection), which never exposes the
credential to the remote host. Enable redirection only where in-session card
use is a hard requirement, and pair it with host hardening and short PIN-cache
lifetimes.

### A.6 Validation checklist (do this before production)

1. `xrdp-baf` package installed (redirection is built in by default);
   `xrdp-chansrv` starts cleanly.
2. RD Core client redirects the card (PC/SC, not USB); `~/.pcsc<display>/`
   appears in the session.
3. `pkcs11-tool --list-slots` in the session shows the client card.
4. An in-session browser completes a client-certificate TLS auth with the card.
5. A **local** IGEL browser still completes a card operation while the session
   holds the card (shared-mode concurrency).
6. Exercise `GET_STATUS_CHANGE`, transactions, and card remove/reinsert for
   RD-Core↔XRDP IOCTL interop; log any unsupported IOCTLs from chansrv.
