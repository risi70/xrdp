# BAF UDS connector

Installs the broker-side glue on a **UDS Enterprise / OpenUDS** server so its
RDP transport can hand each session a single-use **Mode C handle**. UDS keeps
doing the user authentication (LDAP/AD, SAML/OIDC, or a certificate/smart-card
authenticator); this connector turns an authenticated user into a BAF
assertion, registers it with the target VDI's handle service, and returns the
handle.

## Install

From a checkout of this repo:

```bash
sudo packaging/uds/install.sh
```

Or download the self-contained installer tarball from the release repository
([`dist/`](../../dist/)) — no repo checkout needed:

```bash
BASE=https://raw.githubusercontent.com/risi70/xrdp/mvp-broker-assertion/dist
wget "$BASE/baf-uds-connector_0.10.80~baf1.tar.gz" "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar xzf baf-uds-connector_0.10.80~baf1.tar.gz
sudo baf-uds-connector/packaging/uds/install.sh
```

Installs to `/opt/baf-uds` (self-contained venv + broker components), the
`baf-uds-connect` CLI to `/usr/local/bin`, and a config template to
`/etc/baf-uds/`.

## Configure

Edit `/etc/baf-uds/config.yaml` so the values **exactly match** the target
VDI's `/etc/xrdp/sesman.ini [BrokerAuth]` (`issuer`, `audience`, `target`,
`kid`) — a mismatch makes the VDI reject the assertion. Place the broker
signing key (RS256 private, PEM) at `issuer_key`; its public half is the VDI
`TrustAnchor`. For smart-card auth, place the CA at `ca`.

## Use from the UDS RDP transport

After UDS authenticates the user, have the RDP transport call:

```bash
# routing-token channel (no credential fields):
baf-uds-connect --user "$USERNAME" --format cookie
#   -> Cookie: msts=<64-hex handle>      (set as the RDP loadbalanceinfo/cookie)

# one-time-credential channel:
HANDLE=$(baf-uds-connect --user "$USERNAME")
#   -> set the RDP password field to $HANDLE, username to $USERNAME

# JSON for programmatic transports:
baf-uds-connect --user "$USERNAME" --format json
```

Smart-card mode (the card authenticates to the broker first):

```bash
baf-uds-connect --smartcard --p12 /path/user.p12 --pin "$PIN" --format cookie
# or a PKCS#11 token:
baf-uds-connect --smartcard --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
    --token-label user-card --card-cert /path/user.pem --pin "$PIN"
```

The mapped Linux username comes from the certificate identity (SAN/CN); it
must resolve on the VDI via NSS/SSSD.

## Reaching the VDI handle service

`handle_socket` is the target VDI's handle service. `baf_handle_client.py`
speaks its UNIX-socket protocol directly. Deployment options:

- **Co-located** UDS+VDI: a local socket path.
- **Remote** (normal): forward the socket per connection — e.g.
  `ssh -L` / `socat UNIX-LISTEN:... UNIX-CONNECT:...` to a root-owned bridge on
  the VDI, or implement the **C6 mTLS bridge** (a small network front-end for
  the handle service). Until C6 exists, the forwarded-socket path is the
  supported integration; treat the transport as trusted and restrict it to
  the UDS host.

## Files

| File | Purpose |
|---|---|
| `install.sh` | venv + component install |
| `baf-uds-connect` | CLI the RDP transport calls (auth → mint → register → handle) |
| `baf_handle_client.py` | pure-Python, wire-compatible handle-service client |
| `config.example.yaml` | configuration template |

Bundled broker components (`broker_issuer.py`, `smartcard_auth.py`,
`smartcard_login.py`, the assertion schema) are broker-neutral and contain no
XRDP-side code. The connector is the SD-009 C6 reference integration; a native
in-process UDS transport plugin is the long-term productization.
