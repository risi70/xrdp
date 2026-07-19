# BAF RDP Transport for OpenUDS / UDS Enterprise

A production-grade server-side transport plugin that connects OpenUDS
(and the API-compatible UDS Enterprise) to the XRDP Broker
Authentication Framework. Per launch it obtains a BAF assertion from a
trusted broker over mutual TLS, registers it with the target desktop's
Handle service, and hands the client only a **single-use handle** —
never a password, token, or assertion.

The portal experience is multilingual: all user-visible strings ship
with English, German, French, Italian, and Spanish catalogs
(`BAFRDP/locale/`), merged into the server's Django catalogs at install
time.

## How it works

```text
user ──portal (Keycloak SSO)──> OpenUDS ──assigns──> VDI machine
                                   │
                       BAFRDP transport (this plugin)
                                   │
       1. POST /v1/assertions ──> trusted broker  (mutual TLS)
       2. assertion ──stdin/SSH or socket──> Handle service on VDI
       3. single-use handle ──> stock RDP client
                                   │
                  RDP ──> XRDP validates the full BAF chain
```

- The **assertion never leaves the server side** and is never placed in
  a log, URL, command line, or client parameter.
- The client receives the handle through one of the two Broker-RDP
  Handle channels, both compatible with stock RDP clients (mstsc,
  FreeRDP, IGEL OS):
  - **one-time credential** (default): the handle rides the standard
    password parameter of the stock, signed OpenUDS client scripts;
  - **routing token**: an `msts=` cookie merged into the generated RDP
    material (`loadbalanceinfo` / `/load-balance-info`).
- The stock RDP transport is subclassed, so OS support, RDP options,
  and the signed client scripts are reused unchanged; this plugin adds
  no client-side code.

Classic username/password PAM login on the VDI hosts is untouched, per
the BAF core rules (`AGENTS.md`).

## Broker issuance API contract

A production implementation of this API is provided in
`integrations/baf-broker-service/` (see also
`broker-auth/DEPLOYMENT-KEYCLOAK-BAF-XRDP.md`; the reference broker in
`broker-auth/reference-broker/` shows the underlying policy). This
plugin calls:

```text
POST {base_url}/v1/assertions        (mutual TLS, both peers pinned)
{
  "subject": "uds:<user-uuid>",
  "preferred_username": "<portal login>",
  "target": "<machine name or fixed target>",
  "broker_session_id": "uds-<random>",
  "auth_method": ["broker"], "assurance_level": "mfa",
  "device_trust": "unknown"
}
200 -> {"assertion": "<compact JWS, <= 16384 bytes>"}
4xx -> issuance denied (portal shows "not authorized")
```

The broker owns all issuance policy (role checks, per-user target
allowlists, lifetimes) and the BAF signing key. The plugin fails closed
on any anomaly: non-HTTPS URL, TLS failure, oversized or malformed
response, denied issuance, registration failure.

## Handle registration backends

- **SSH (recommended for remote VDI hosts):** runs `baf-uds-register`
  (from `packaging/uds/`) on the desktop host; the assertion travels on
  stdin. Use a dedicated account with a forced command:

  ```text
  # /home/baf-register/.ssh/authorized_keys on the VDI host
  command="baf-uds-register --target baflab-vdi-01 --ttl 90 --format json",restrict ssh-ed25519 AAAA...
  ```

  The account needs group access to `/run/xrdp/baf-handle.sock` only.
  Host keys are pinned via a dedicated `known_hosts` file;
  `StrictHostKeyChecking=yes` and `BatchMode` are hardwired.

- **Socket:** speaks the SEQPACKET Handle protocol directly
  (`BAFRDP/core/handle_socket.py`, vendored from
  `broker-auth/tools/baf_handle_client.py` and drift-checked at build
  and test time). For brokers co-located with the VDI host or a
  separately authenticated, protected forwarding of the socket.

## Install

```sh
integrations/openuds-baf/build-plugin.sh
tar -xzf integrations/openuds-baf/out/xrdp-baf-openuds-plugin-*.tar.gz
sudo ./xrdp-baf-openuds-plugin-*/install.sh          # autodetects the uds tree
sudo ./xrdp-baf-openuds-plugin-*/install.sh --uds-path /usr/lib/python3/dist-packages/uds
```

Then restart the UDS server processes and create a transport of type
**"RDP (BAF broker)"** in the administration UI. All BAF settings live
on the **BAF Broker** tab; TLS material and the SSH registration key
belong under `/etc/uds/baf/` (root-owned, keys mode 0600).

Supported servers: OpenUDS 4.x and the 3.6 LTS line (both attribute
spellings and form-field APIs are handled by `BAFRDP/_compat.py`; the
plugin refuses to load on an unrecognized API rather than guessing).

## Security model

- Trust anchors: OpenUDS never sees the BAF signing key; XRDP never
  sees Keycloak tokens; the client never sees the assertion.
- The handle is a random single-use server-side reference with a 1-120
  second lifetime, consumed atomically by the XRDP Handle service;
  replay is rejected by the trusted replay service.
- Logs carry error codes and non-secret diagnostics only. Portal users
  get localized, non-technical messages (one per error code).
- Everything fails closed; a broker or registration outage denies the
  launch and never falls back to password prompting.

## Development

```sh
python3 -m pytest integrations/openuds-baf/tests   # 42 tests, no OpenUDS needed
integrations/openuds-baf/tools/update-locales.py   # regenerate catalogs
```

Portal strings live in `BAFRDP/transport.py` wrapped in `_noop()`; the
locale tests extract them from the source, so a new or changed string
fails the suite until every catalog is updated.
