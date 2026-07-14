# Broker Authentication Framework architecture

This branch contains an experimental Broker Authentication Framework (BAF) for
XRDP.

BAF adds broker-authenticated pre-logon support while preserving the existing
XRDP username/password PAM path. The shipped ingress is **Broker-RDP Handle** (SD-009):
stock, unmodified RDP clients present a single-use server-side handle. The
RDSAAD-style pre-logon exchange is also implemented. Both fail closed and run
the full sesman/xrdp-sesexec chain — assertion validation, trusted replay,
NSS/SSSD identity binding, UID 0 rejection and PAM preconditions — before a
session starts. See [broker-auth/MODE-C-ONE-TIME-HANDLE.md](broker-auth/MODE-C-ONE-TIME-HANDLE.md).

## Goals

- Add broker-auth pre-logon support to XRDP.
- Use standard RDP-compatible mechanisms as far as possible.
- Allow IGEL OS and other clients to remain standard RDP clients.
- Support generic broker assertions without hard-coding UDS, Keycloak, or
  Microsoft Entra behavior.
- Preserve classic XRDP username/password PAM login.
- Preserve Linux account authority through NSS/SSSD and PAM.

## Main Requirements

- Broker-auth is build-gated by `--enable-broker-auth`.
- Broker-auth and RDSAAD mode are disabled by default at runtime.
- RDSAAD-style ingress carries `rdp_assertion` in the RDP pre-logon exchange.
- Assertions are JWT/JWS compact assertions validated by the generic BAF
  provider.
- Trusted replay service is mandatory for live activation.
- Linux identity comes from NSS/SSSD-compatible lookup, not token UID/GID
  fields.
- UID 0 is rejected by default.
- PAM account approval and PAM session/credential lifecycle are required before
  session startup.
- Username/password assertion overloading is forbidden.
- No custom IGEL client, FreeRDP plugin, dynamic virtual channel, or endpoint
  helper is required.
- Raw assertions are not logged.
- Ambiguous or unavailable dependencies fail closed.

## Important Architecture Decisions

- SD-002 separates assertion validation from Linux identity binding.
- SD-003 splits Phase 4a prerequisites from Phase 4b live activation and
  requires effective transport-size bounds.
- SD-004 makes the trusted replay service mandatory for live activation.
- SD-005 preserves standard RDP client neutrality.
- SD-006 and SD-007 define one-time server-side handles; SD-009 promotes them
  from superseded to the shipped **Broker-RDP Handle** production ingress for stock RDP
  clients.
- SD-008 defines the RDSAAD-style pre-logon assertion ingress (also implemented).
- SD-009 defines the robust ingress tracks; Broker-RDP Handle (one-time handle) is the
  shipped MVP path (see
  [broker-auth/MODE-C-ONE-TIME-HANDLE.md](broker-auth/MODE-C-ONE-TIME-HANDLE.md)).

## High-Level Flow

The target live flow is:

```text
RDSAAD negotiation
-> TLS
-> Server Nonce
-> Authentication Request with rdp_assertion
-> BAF validator
-> trusted replay service
-> NSS/SSSD identity binding
-> UID 0 rejection
-> PAM account/session lifecycle
-> existing XRDP session startup as the resolved Linux user
```

Authentication Result `S_OK` is valid only after that complete chain has
authorized the connection and the existing session path can continue.

## Security Model

The assertion is credential-grade material. Validator success alone is not
session authorization.

Before a live session can start, BAF requires:

- assertion validation;
- trusted replay reservation;
- validated broker capability creation;
- NSS/SSSD-compatible identity binding;
- UID 0 rejection by default;
- PAM account approval;
- PAM session/credential lifecycle readiness.

Token UID/GID values are never trusted. Token roles or groups are not treated as
Unix group membership. Raw assertion bytes are cleared after handoff and are not
logged.

## Current Status

Implemented pieces include:

- BAF JWT validator and transport tests.
- Trusted replay service.
- NSS/SSSD-compatible identity binding.
- PAM precondition support for prevalidated broker login.
- RDSAAD helper/parser code for Server Nonce, Authentication Request, and
  Authentication Result JSON payloads.
- Runtime-gated `PROTOCOL_RDSAAD` selection in `libxrdp/xrdp_iso.c`.
- A post-TLS/pre-MCS exchange hook in `xrdp_sec_incoming()`.
- A libxrdp-to-xrdp owner callback for RDSAAD preauth before MCS.
- SCP/EICP broker preauth dispatch from xrdp through sesman to xrdp-sesexec.
- Session-ready BAF `login_info` creation after JWT validation, trusted replay,
  NSS/SSSD identity binding, UID 0 rejection, and PAM broker preconditions.
- Session-bound adoption of the authenticated sesman transport by `xrdp_mm`
  after MCS has created the normal session-management layer.
- A Phase 5 broker-neutral reference broker and isolated UDS simulator adapter
  under `broker-auth/reference-broker/`, proving broker interoperability
  without adding UDS-specific behavior to XRDP core. Phase 5 supports Mode A
  native RDSAAD clients and Mode B broker gateway RDSAAD; both use the same
  XRDP-side RDSAAD ingress.
- SD-009 Wave 1: RDSAAD nonce plumb-through with the optional
  `urn:baf:ts_nonce` extension claim and the fail-closed
  `RequireNonceBinding` gate, and Broker-RDP Handle ingress for stock
  clients through both an X.224 routing-token channel and a one-time
  credential channel (see `broker-auth/MODE-C-ONE-TIME-HANDLE.md`). The
  SD-006 handle service is promoted from superseded to production for
  Broker-RDP Handle.

The current production bridge emits `S_OK` only after sesman/xrdp-sesexec
returns full BAF preauth approval. Failure to parse, validate, reserve replay,
bind identity, pass PAM account checks, or obtain trusted configuration returns
an Authentication Result failure and does not continue to MCS.

## Current Limitations / Deferred Work

Trusted BAF runtime configuration is owned by sesman/xrdp-sesexec through the
local [BrokerAuth] sesman.ini section, not xrdp_client_info. It supplies
fail-closed defaults for provider, issuer, key id, trust anchor, audience, local
target, service replay, UID 0 rejection, assertion size, and the session-start
gate. `AllowSessionStart` remains false by default and must be enabled by
trusted local configuration before live RDSAAD activation can succeed.

Remaining work is operational and interoperability focused:

- deploy trusted issuer/key/trust-anchor configuration and replay service;
- exercise an end-to-end RDSAAD-capable client against the live bridge;
- replace the Phase 5 UDS simulator with a production UDS API adapter if
  required by deployment policy;
- decide when the superseded handle service can be removed from normal builds.

One-time assertion-handle code from SD-006/SD-007 remains in the tree as
superseded experimental/test coverage until the RDSAAD live path fully replaces
it. It is not the selected MVP production ingress.

Deferred work also includes:

- UDS reference broker integration in Phase 5;
- broader client interoperability testing;
- optional Microsoft/Entra-specific validation only as isolated deployment
  policy;
- cluster-wide replay, if needed;
- production configuration hardening.

## Phase 6 KVM Integration Lab

Phase 6 adds a KVM/libvirt integration lab under `test-lab/` for exercising the
BAF/RDSAAD architecture with a host `xfreerdp` client, an OpenUDS-compatible
broker VM, and an Ubuntu 24.04 VDI VM running XRDP from this source tree. The
lab remains outside XRDP core and does not introduce OpenUDS-specific behavior
into `libxrdp`, `xrdp`, `sesman`, `sesexec`, `libipm`, or `common`.

The initial Phase 6 implementation provides an OpenUDS-compatible reference
mode. Real OpenUDS deployment can replace the adapter/configuration in the
`openuds-broker` VM while preserving the broker-neutral XRDP-side BAF/RDSAAD
ingress. Stock `xfreerdp` client assertion injection is documented as a skipped
wire-level test unless a deployment provides a compatible RDSAAD-capable client
or gateway path.
