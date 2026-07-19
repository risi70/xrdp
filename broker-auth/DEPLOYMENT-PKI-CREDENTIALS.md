# PKI Credential Inventory for the BAF End-to-End Chain

This document lists every key and certificate needed to operate the full
chain — IGEL client → OpenUDS portal (Keycloak SSO) → BAFRDP transport
(`integrations/openuds-baf/`) → issuance service
(`integrations/baf-broker-service/`) → Handle registration → XRDP — under
the assumption that a **central PKI** (offline root CA plus online issuing
CAs, with CRL/OCSP) already exists. The lab substitutes the central PKI's
hardware tokens with **virtual smart cards attached to the VMs** (see the
last section).

Provisioning tooling: `integrations/pki/baf-pki-setup.sh` implements
this inventory — lab mode creates a stand-in CA hierarchy and issues
everything; CSR mode generates keys and CSRs for the real central PKI.

## What the central PKI must provide

| CA | Purpose | Notes |
|----|---------|-------|
| Root CA | Trust anchor for everything below | Distributed to every host and to the IGEL client trust store |
| TLS issuing CA | All `serverAuth` certificates (K2, K4, K5, K6, K9) | Standard server profile |
| Client-auth issuing CA | `clientAuth` certificates for BAF front ends (K3) | **Keep this CA narrow.** The issuance service's `client_ca` authorizes assertion requests; a broad CA here would let any corporate client cert request assertions. A dedicated sub-CA (or a dedicated profile) is strongly recommended. |
| SSH CA (optional) | SSH host/user certificates instead of raw keys (K10, K11) | Removes `known_hosts`/`authorized_keys` pinning churn |

## Credential inventory

| ID | Credential | Type | Subject / identity | Private key holder | Who must trust it (and where) |
|----|-----------|------|--------------------|--------------------|-------------------------------|
| K1 | **BAF assertion signing key** | RSA ≥ 2048, RS256, identified by `kid` (not a TLS cert; the PKI may additionally certify it for inventory/rotation governance) | `kid` = e.g. `baf-signing-key-01`; issuer URL as configured | Broker host (issuance service `private_key`) | Every VDI host: public key as `TrustAnchor` in `sesman.ini` `[BrokerAuth]` (e.g. `/etc/xrdp/baf-broker-public.pem`), with matching `Issuer` and `KeyId` |
| K2 | **Issuance service TLS server cert** | X.509 serverAuth | SAN = broker service FQDN | Broker host (`tls_cert`/`tls_key` in the service config) | OpenUDS server: CA chain file referenced by the transport's "Broker CA bundle" field |
| K3 | **OpenUDS mTLS client cert** | X.509 clientAuth | **CN must equal an entry in the service's `allowed_client_cn`** (e.g. `CN=uds-server`) | OpenUDS server (`/etc/uds/baf/uds-client.pem` + `.key`) | Issuance service: issuing CA chain as `client_ca`, plus the CN allowlist |
| K4 | **OpenUDS portal TLS cert** | X.509 serverAuth | SAN = portal FQDN | OpenUDS server | Users' browsers and the IGEL client trust store |
| K5 | **UDS tunnel server TLS cert** (only if the tunnel is deployed) | X.509 serverAuth | SAN = tunnel FQDN | Tunnel host | UDS clients / IGEL |
| K6 | **Keycloak TLS cert** | X.509 serverAuth | SAN = Keycloak FQDN | Keycloak host | Browsers, OpenUDS (OIDC/SAML metadata fetch), and — if the broker later validates Keycloak tokens directly — the issuance service |
| K7 | **Keycloak ↔ OpenUDS federation credential** | OIDC confidential client secret, or SAML SP signing/encryption cert (the SAML cert is PKI-issuable) | OpenUDS authenticator identity in the `vdi` realm | OpenUDS server | Keycloak realm configuration |
| K8 | **Keycloak realm token-signing keys** | Managed internally by Keycloak, published via JWKS | realm `vdi` | Keycloak | Token consumers (portal flow); *not* issued by the central PKI |
| K9 | **XRDP per-host TLS cert** | X.509 serverAuth (replaces the self-signed pair the deb postinst generates) | SAN = VDI host FQDN | Each VDI host (`/etc/xrdp/cert.pem` + `key.pem`, wired via `certificate=`/`key_file=` in `xrdp.ini`) | IGEL / stock RDP clients (their trust store; removes the lab-only "accept self-signed" step) |
| K10 | **Handle-registration SSH keypair** | ed25519 (or an SSH user certificate from the SSH CA) | Registration account `baf-register` | OpenUDS server (transport field "SSH identity file", default `/etc/uds/baf/registrar_ed25519`) | Every VDI host: `authorized_keys` of `baf-register` with the forced `baf-uds-register` command |
| K11 | **VDI SSH host keys** | ed25519 host keys (or SSH host certificates) | Each VDI host | Each VDI host | OpenUDS server: pinned in the transport's `known_hosts` file (`/etc/uds/baf/known_hosts`) |
| K12 | **User smart-card auth certs** (lab; optional in production) | X.509 clientAuth for Keycloak X.509/browser login | One per test user (`bafuser`, …) | User smart card (lab: virtual smart card on the IGEL VM) | Keycloak X.509 authenticator (client-cert CA config) |
| K13 | IGEL device/UMS certificates | IGEL-managed | Device identity | IGEL OS / UMS | Out of BAF scope; listed for completeness |

Supporting trust-store files derived from the above (no private keys):
the root/issuing CA chain on every host, the broker CA bundle on the
OpenUDS server (for K2), the client CA bundle on the broker host (for
K3), and the `TrustAnchor` public key on every VDI host (from K1).

## Distribution summary per host

- **Broker host**: K1 private, K2 pair, client CA bundle + CN allowlist.
- **OpenUDS server**: K3 pair, K4 pair, K7, K10 private, `known_hosts`
  (K11 pins), broker CA bundle.
- **Keycloak host**: K6 pair, K8 (internal), K12 issuing CA reference.
- **Each VDI host**: K9 pair, K1 public (`TrustAnchor`), `baf-register`
  `authorized_keys` (K10 public, forced command), K11 host keys.
- **IGEL client**: root CA (trusts K4/K5/K9), K12 card (lab).

Rotation notes: K1 rotates by issuing with a new `kid` and installing
the new `TrustAnchor` on VDI hosts before switching the service config
(single-anchor limitation today — dual-anchor support is a known
deferred item). TLS certs rotate on normal PKI cadence; K3 rotation
must keep the CN stable or update `allowed_client_cn` in lockstep. K10
rotation touches every VDI host's `authorized_keys` unless SSH
certificates are used.

## Option: HashiCorp Vault as the secrets backend

Vault is used **on the server side only**: broker host, OpenUDS server,
Keycloak host, and the VDI hosts. Clients are never Vault clients — the
IGEL device holds only the root CA in its trust store plus the user's
smart card (K12); user and device credentials (K12, K13) stay on
cards/local stores and are merely *issued* by the PKI.

Within that scope Vault can implement the inventory without any code
changes to the BAF components, because every server component reads PEM
files from configured paths — a **Vault Agent** per server host
authenticates, renders the material to exactly those paths (owner/mode
preserved), keeps it renewed, and reloads the service:

| Vault engine | Covers | Notes |
|--------------|--------|-------|
| PKI (server mount) | K2, K4, K5, K6, K9 | Vault acts as (or is an intermediate of) the TLS issuing CA; short TTLs with automatic renewal replace manual rotation |
| PKI (dedicated client-auth mount) | K3 | A separate mount/role with pinned CN keeps the issuance service's `client_ca` narrow, as required above |
| SSH | K10, K11 | The SSH engine signs short-lived user and host certificates; the forced command can ride the certificate's `force-command` critical option, enforced even if `authorized_keys` is misconfigured |
| KV v2 | K7 (OIDC client secret), misc. static values | |
| Transit | K1 (future) | A non-exportable `rsa-2048` transit key signing `sha2-256`/`pkcs1v15` is exactly RS256; the issuance service would call Vault per assertion instead of holding the key. Requires a service integration (parallel to the PKCS#11 note below). Until then, keep K1 in KV/exportable-transit and template it to the file the service reads. |

Not Vault-managed: K8 (Keycloak-internal JWKS), K12/K13 (client-side —
user cards and IGEL device identity), and the `TrustAnchor`
distribution to VDI hosts (public material; can be templated from Vault
for convenience but is not a secret).

Host authentication to Vault: AppRole or TLS-certificate auth per
server host, scoped by policy to exactly its rows in the distribution
summary. In the lab, the **server VMs'** virtual smart cards pair
naturally with Vault's TLS cert-auth method: each card holds only that
host's Vault bootstrap identity, and every runtime secret is delivered
short-lived by Vault — fewer keys on the cards, central revocation.
The IGEL VM's card is unaffected: it keeps the user login certificate
(K12) and never talks to Vault.

## Lab mock-up: virtual smart cards on the VMs

The lab emulates the central PKI's hardware-backed keys with virtual
smart cards attached to the Proxmox/KVM guests (QEMU CCID:
`-device usb-ccid -device ccid-card-emulated` with an NSS-backed store,
or `softhsm2` where only a PKCS#11 token — not a card reader — is
needed). Suggested card-per-VM mapping:

| VM | Card contents |
|----|---------------|
| `baflab-broker` | K1 (signing-ceremony demonstration), K2 |
| `baflab-uds` | K3, K10 |
| `baflab-vdi-01` | K9 |
| `baflab-igel12` | K12 (user login card for Keycloak X.509) |

Honest capability notes for the mock-up:

- **Card-backed at runtime today**: K10 — OpenSSH supports
  `PKCS11Provider` natively; the transport's SSH registrar would need a
  small enhancement (an option that emits `-o PKCS11Provider=...`
  instead of `-i`). K12 — browser/Keycloak X.509 login on IGEL works
  against a CCID card via pcsc.
- **File-backed at runtime today**: K1, K2, K3, K9 — the issuance
  service and the plugin load PEM files through Python's `ssl`/PyJWT,
  and xrdp reads PEM paths from `xrdp.ini`; none of these speak PKCS#11
  yet. For the lab, keep the authoritative copy on the card and treat
  extraction to the runtime file as the provisioning ceremony;
  PKCS#11/engine support in the services is future work if
  non-exportable keys become a requirement.
- The virtual smart cards here hold **infrastructure keys**; they are
  orthogonal to the in-session smart-card *forwarding* work
  (MS-RDPESC), which passes a user's card through RDP into the desktop
  session. The same virtual card on the IGEL VM can, however, double as
  the test card for that forwarding path.
