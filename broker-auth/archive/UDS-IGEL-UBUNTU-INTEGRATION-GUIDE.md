# UDS Enterprise / IGEL OS 12 / Ubuntu 24.04 BAF Integration Guide

This guide describes how to integrate an existing UDS Enterprise environment,
standard IGEL OS 12 endpoints, and Ubuntu 24.04 VDI targets with the XRDP
Broker Authentication Framework (BAF) branch.

The supported architecture keeps XRDP core broker-neutral. UDS-specific logic
belongs in the broker/gateway/reference adapter layer, not in `libxrdp`, `xrdp`,
`sesman`, `sesexec`, `libipm`, or `common`.

## 1. Choose the Deployment Mode

### Mode A: Native RDSAAD Client Mode

Use this only if the RDP client/broker stack can send an RDSAAD Authentication
Request containing a BAF `rdp_assertion`.

```text
IGEL OS 12 / compatible RDP client
-> XRDP RDSAAD pre-logon exchange
-> BAF validation
-> replay service
-> NSS/SSSD identity binding
-> PAM account/session checks
-> Ubuntu session
```

Current limitation: stock client documentation must be verified for arbitrary
`rdp_assertion` injection. Do not assume IGEL OS 12 can inject a custom BAF
assertion until packet-level interoperability proves it.

### Mode B: Broker Gateway RDSAAD Mode

Use this when IGEL OS 12 cannot inject the BAF assertion itself.

```text
IGEL OS 12 standard RDP client
-> UDS Enterprise / broker gateway
-> gateway performs RDSAAD/BAF toward XRDP
-> XRDP validates BAF assertion
-> Ubuntu session
```

This is the preferred fallback for standard IGEL clients. It avoids custom IGEL
clients, FreeRDP plugins, dynamic virtual channels, and username/password
assertion overloading.

## 2. Prerequisites

### UDS Enterprise / Broker Side

- Existing UDS Enterprise deployment.
- Broker/gateway host able to reach Ubuntu VDI targets over RDP/TCP 3389.
- BAF signing key pair generated and protected on broker/gateway side.
- Broker adapter capable of mapping UDS objects to BAF concepts:
  - UDS user -> `sub` and `preferred_username`.
  - UDS service/pool/resource -> target policy context.
  - UDS assigned VM -> `target`.
  - UDS session -> `broker_session_id`.
  - UDS authentication method -> `auth_method` / `assurance_level`.
- No token UID/GID or UDS group data may be treated as Unix identity authority.

### IGEL OS 12 Side

- Standard RDP profile pointing either directly to the Ubuntu VDI target
  (Mode A) or to the broker gateway (Mode B).
- No custom endpoint helper, dynamic virtual channel, FreeRDP plugin, or
  username/password assertion transport.
- Smartcard redirection may be enabled for in-session application use, but it is
  separate from BAF broker SSO.

### Ubuntu 24.04 VDI Side

- Ubuntu 24.04 server or desktop target.
- XRDP built from this branch with broker-auth enabled.
- `xorgxrdp` / desktop environment installed for graphical sessions.
- NSS/SSSD or local account resolution for broker-resolved Linux usernames.
- PAM service configured for XRDP account/session checks.
- Trusted replay service available.
- Trusted local BAF runtime config installed on the VDI host.

## 3. Build Packages

From this repository on the build host, build the VDI and broker artifacts:

```bash
./bootstrap
./configure --disable-rfxcodec --enable-broker-auth
make -j"$(nproc)"
make -C tests/baf check
python3 tests/baf/test_security_contract.py
python3 tests/baf/test_pam_broker_contract.py
```

If using the Phase 6 local package artifacts, build or locate:

```text
test-lab/kvm/artifacts/packages/xrdp-baf-vdi_*.deb
test-lab/kvm/artifacts/packages/openuds-baf-reference_*.deb
```

The `xrdp-baf-vdi` package is for Ubuntu VDI targets. The
`openuds-baf-reference` package is for broker/gateway-side reference tools and
adapter scaffolding.

## 4. Install on Ubuntu 24.04 VDI Targets

Copy the VDI package to the Ubuntu target and install it:

```bash
sudo apt-get update
sudo apt-get install -y xorgxrdp xfce4 dbus-x11 ssl-cert libjwt0 libjansson4
sudo apt-get install -y ./xrdp-baf-vdi_*.deb
```

If your distro provides `libjwt2` instead of `libjwt0`, install that package
instead.

Enable services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now xrdp-sesman xrdp
```

Verify binaries:

```bash
/usr/local/sbin/xrdp --version || true
/usr/local/sbin/xrdp-sesman --help || true
/usr/local/sbin/xrdp-baf-replayd --help || true
```

## 5. Configure Linux Identity

BAF does not trust user identity from token UID/GID/group claims. The resolved
Linux username must exist through NSS/SSSD-compatible lookup.

For a local smoke test:

```bash
sudo adduser --disabled-password --gecos "BAF Test User" bafuser
getent passwd bafuser
```

For production:

- Configure SSSD/LDAP/AD/FreeIPA as normal Linux identity infrastructure.
- Ensure `preferred_username` in the BAF assertion maps to a resolvable Linux
  username.
- Ensure UID 0 is not mapped or permitted.
- Do not map token roles/groups directly to Unix groups.

## 6. Configure PAM

Classic XRDP login still uses `pam_authenticate()`. Broker-auth must not.
Broker-auth requires PAM account approval and session/credential lifecycle.

Confirm the XRDP PAM service exists:

```bash
sudo test -f /etc/pam.d/xrdp-sesman
```

Configure account/session policy for the target environment. For example,
ensure account rules allow intended VDI users and deny disabled/expired users.
Test both success and denial cases before enabling broker-auth session start.

## 7. Configure Trusted Replay Service

Live BAF activation requires the trusted replay service. Process-local replay is
not valid for production live activation.

Create runtime directory:

```bash
sudo install -d -m 0755 /run/xrdp-baf
```

Start the replay service according to the built binary and local policy. Example
service wiring from Phase 6 uses:

```text
/usr/local/sbin/xrdp-baf-replayd --socket /run/xrdp-baf/replay.sock
```

Verify the service socket exists:

```bash
sudo test -S /run/xrdp-baf/replay.sock
```

## 8. Configure Trusted BAF Runtime on Ubuntu

Install the broker public key/trust anchor on the VDI host:

```bash
sudo install -d -m 0750 /etc/xrdp/baf
sudo install -m 0640 reference-broker.pub /etc/xrdp/baf/reference-broker.pub
```

Configure the trusted local BAF runtime. Exact file/section names must match the
current branch configuration model used by sesman/xrdp-sesexec. A Phase 6-style
example is:

```ini
BrokerAuthEnabled=true
RDSAADEnabled=true
Provider=jwt
TrustAnchor=/etc/xrdp/baf/reference-broker.pub
ExpectedAudience=xrdp://ubuntu-vdi-01
LocalTarget=ubuntu-vdi-01
MaxAssertionSize=16384
ReplayBackend=service
ReplaySocket=/run/xrdp-baf/replay.sock
RejectUid0=true
AllowSessionStart=true
```

Important:

- These values must come from trusted local VDI configuration, not from the RDP
  client.
- `AllowSessionStart` must remain false until replay, identity binding, PAM, and
  end-to-end authorization are proven in the environment.
- Use target-specific `ExpectedAudience` and `LocalTarget` values.

Restart services after configuration changes:

```bash
sudo systemctl restart xrdp-sesman xrdp
```

## 9. Install Broker/Gateway Reference Tools

On the UDS Enterprise broker/gateway host:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-jwt python3-cryptography
sudo apt-get install -y ./openuds-baf-reference_*.deb
```

Verify wrappers:

```bash
openuds-baf-issue-assertion --help
openuds-baf-uds-adapter --help || true
```

Generate a signing key on the broker/gateway host. Do not commit or copy the
private key to VDI targets.

```bash
sudo install -d -m 0750 /etc/openuds-baf-reference
sudo openssl genrsa -out /etc/openuds-baf-reference/baf-reference.key 2048
sudo openssl rsa -in /etc/openuds-baf-reference/baf-reference.key \
  -pubout -out /etc/openuds-baf-reference/baf-reference.pub
```

Copy only the public key to Ubuntu VDI targets as the trust anchor.

## 10. Issue a Test Assertion

On the broker/gateway host:

```bash
openuds-baf-issue-assertion \
  --private-key /etc/openuds-baf-reference/baf-reference.key \
  --kid uds-baf-lab-1 \
  --issuer https://uds.example.local/baf \
  --audience xrdp://ubuntu-vdi-01 \
  --target ubuntu-vdi-01 \
  --subject uds-user-123 \
  --preferred-username bafuser \
  --broker-session-id uds-session-123 \
  --auth-method smartcard \
  --assurance-level mfa
```

The command prints a compact JWT/JWS. Treat it as credential-grade material. Do
not log it in production.

## 11. Integrate UDS Mapping

Use the adapter boundary to map UDS data to BAF claims:

```text
UDS authenticated user       -> sub, preferred_username
UDS session id               -> broker_session_id
UDS assigned Ubuntu resource -> target
UDS service/pool policy      -> audience or policy context
UDS auth context             -> auth_method, assurance_level
```

Rules:

- UDS groups are not Unix groups.
- UDS user IDs are not Linux UIDs.
- The Ubuntu target resolves the Linux username through NSS/SSSD.
- The Ubuntu target enforces PAM account/session policy.
- Replay is enforced by the XRDP-side trusted replay service.

## 12. Configure RDP Launch

### Mode A

Configure the RDP launch only if the client/broker stack can send RDSAAD
`rdp_assertion` data in the standard pre-logon exchange.

Expected observations:

- `PROTOCOL_RDSAAD` is negotiated.
- XRDP sends Server Nonce.
- Client sends Authentication Request with `rdp_assertion`.
- XRDP sends Authentication Result `S_OK` only after full authorization.

### Mode B

Configure IGEL OS 12 to connect to the broker/gateway using a standard RDP
profile. The gateway then opens the RDSAAD/BAF connection to XRDP using the BAF
assertion. This keeps the endpoint unmodified.

Expected observations:

- IGEL uses normal RDP behavior.
- Gateway owns assertion creation/injection.
- XRDP sees only the standard RDSAAD ingress.
- Ubuntu session starts as the NSS-resolved Linux user.

## 13. Validation Checklist

On Ubuntu VDI:

```bash
getent passwd bafuser
sudo test -S /run/xrdp-baf/replay.sock
sudo systemctl status xrdp-sesman xrdp
```

From a client or gateway:

- Valid assertion succeeds.
- Wrong audience fails.
- Wrong target fails.
- Expired assertion fails.
- Replayed assertion fails.
- Unknown Linux user fails.
- UID 0 user fails.
- PAM-denied user fails.
- Classic password login remains unchanged.

## 14. Troubleshooting

### XRDP rejects all broker logins

Check trusted runtime config, trust anchor path, replay socket, and
`AllowSessionStart`.

### Assertion validates but session does not start

Check NSS/SSSD resolution, UID 0 rejection, PAM account rules, and PAM session
lifecycle.

### IGEL cannot send assertion

Use Mode B gateway. Do not overload username/password fields and do not install
custom endpoint helpers for the MVP path.

### Replay errors

Ensure the trusted replay service is running and reachable at the configured
socket. Reusing the same assertion must fail.

## 15. Rollback

On Ubuntu VDI:

```bash
sudo systemctl disable --now xrdp xrdp-sesman || true
sudo apt-get remove xrdp-baf-vdi
sudo rm -rf /etc/xrdp/baf /run/xrdp-baf
```

On broker/gateway:

```bash
sudo apt-get remove openuds-baf-reference
sudo rm -rf /etc/openuds-baf-reference
```

Do not remove existing UDS Enterprise components unless they were installed only
for this lab.
