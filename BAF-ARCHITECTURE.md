# Broker Authentication Framework architecture

This branch contains an experimental Broker Authentication Framework (BAF) for
XRDP.

BAF adds broker-authenticated pre-logon support while preserving the existing
XRDP username/password PAM path. Keycloak is the primary user-facing IdP. The
broker validates Keycloak/OIDC and issues a distinct broker-neutral BAF
assertion; XRDP validates only the BAF assertion.

The branch includes **Broker-RDP Handle** and an RDSAAD-style pre-logon
exchange. Production ingress selection between SD-008 and proposed SD-009 is
unresolved. RDSAAD is only an optional MS-RDPBCGR-compatible assertion envelope
and does not provide Microsoft identity integration or compatibility with stock
Entra clients carrying BAF assertions. Both implemented paths fail closed and
use the sesman/xrdp-sesexec authorization chain before a session starts. See
[broker-auth/BROKER-RDP-HANDLE.md](broker-auth/BROKER-RDP-HANDLE.md).

> **Codename:** Broker-RDP Handle is called **"Mode C"** in the source and
> config (identifiers `modec_*`, keys `ModeCOneTimeCredential` /
> `broker_auth_modec_ingress_enabled`) — its SD-009 track name, after the
> RDSAAD tracks. The codename does not resolve the SD-008/SD-009 decision. See
> BROKER-RDP-HANDLE.md, "Naming".

## Goals

- Add broker-auth pre-logon support to XRDP.
- Use standard RDP-compatible mechanisms as far as possible.
- Allow IGEL OS and other clients to remain standard RDP clients.
- Keep Keycloak/OIDC validation at the broker and generic BAF assertion
  validation in XRDP core.
- Preserve classic XRDP username/password PAM login.
- Preserve Linux account authority through system NSS and PAM.

## Main Requirements

- Broker-auth is build-gated by `--enable-broker-auth`.
- Broker-auth and RDSAAD mode are disabled by default at runtime.
- Optional RDSAAD-style ingress carries `rdp_assertion` in the RDP pre-logon
  exchange; it is an assertion envelope, not a Microsoft identity integration.
- Broker-RDP Handle remains included while ingress selection is unresolved.
- Assertions are JWT/JWS compact assertions validated by the generic BAF
  provider.
- Trusted replay service is mandatory for live activation.
- Linux identity comes from system NSS lookup, not token UID/GID
  fields.
- UID 0 is rejected by default.
- PAM account approval and PAM session/credential lifecycle are required before
  session startup.
- Username/password assertion overloading is forbidden.
- No custom IGEL client, FreeRDP plugin, dynamic virtual channel, or endpoint
  helper is required.
- Raw assertions are not logged.
- Ambiguous or unavailable dependencies fail closed.
- LDAP provisioning or synchronization, SSSD configuration or availability,
  Active Directory, Kerberos, domain join, and Microsoft Entra are out of scope
  and are not deployment, release, or lab prerequisites.

## Important Architecture Decisions

- SD-002 separates assertion validation from Linux identity binding.
- SD-003 splits Phase 4a prerequisites from Phase 4b live activation and
  requires effective transport-size bounds.
- SD-004 makes the trusted replay service mandatory for live activation.
- SD-005 preserves standard RDP client neutrality.
- SD-006 and SD-007 define one-time server-side handles used by the included
  **Broker-RDP Handle** implementation.
- SD-008 defines the optional RDSAAD-style pre-logon assertion envelope.
- SD-009 proposes robust ingress tracks, including Broker-RDP Handle (see
  [broker-auth/BROKER-RDP-HANDLE.md](broker-auth/BROKER-RDP-HANDLE.md)).
- SD-009 remains proposed, so these documents do not select it over SD-008 or
  treat SD-008 as the final production choice.

## High-Level Flow

The target live authorization flow is:

```text
Keycloak OIDC authentication
-> broker validates OIDC identity and authorization context
-> broker issues a distinct target-bound BAF assertion
-> enabled BAF ingress transports or resolves that assertion
-> BAF validator
-> trusted replay service
-> system NSS identity binding
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
- system NSS identity binding;
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
- system NSS identity binding.
- PAM precondition support for prevalidated broker login.
- RDSAAD helper/parser code for Server Nonce, Authentication Request, and
  Authentication Result JSON payloads.
- Runtime-gated `PROTOCOL_RDSAAD` selection in `libxrdp/xrdp_iso.c`.
- A post-TLS/pre-MCS exchange hook in `xrdp_sec_incoming()`.
- A libxrdp-to-xrdp owner callback for RDSAAD preauth before MCS.
- SCP/EICP broker preauth dispatch from xrdp through sesman to xrdp-sesexec.
- Session-ready BAF `login_info` creation after JWT validation, trusted replay,
  system NSS identity binding, UID 0 rejection, and PAM broker preconditions.
- Session-bound adoption of the authenticated sesman transport by `xrdp_mm`
  after MCS has created the normal session-management layer.
- A Phase 5 broker-neutral reference broker and isolated UDS simulator adapter
  under `broker-auth/reference-broker/`, proving broker interoperability
  without adding UDS-specific behavior to XRDP core.
- SD-009 Wave 1: RDSAAD nonce plumb-through with the optional
  `urn:baf:ts_nonce` extension claim and the fail-closed
  `RequireNonceBinding` gate, and Broker-RDP Handle ingress for stock
  clients through both an X.224 routing-token channel and a one-time
  credential channel (see `broker-auth/BROKER-RDP-HANDLE.md`). The
  SD-006 handle service remains included for Broker-RDP Handle.

The implemented RDSAAD bridge emits `S_OK` only after sesman/xrdp-sesexec
returns full BAF preauth approval. Failure to parse, validate, reserve replay,
bind identity, pass PAM account checks, or obtain trusted configuration returns
an Authentication Result failure and does not continue to MCS.

## Current Limitations / Deferred Work

Trusted BAF runtime configuration is owned by sesman/xrdp-sesexec through the
local [BrokerAuth] sesman.ini section, not xrdp_client_info. It supplies
fail-closed defaults for provider, issuer, key id, trust anchor, audience, local
target, service replay, UID 0 rejection, assertion size, and the session-start
gate. `AllowSessionStart` remains false by default and must be enabled by
trusted local configuration before live broker-auth activation can succeed.

Remaining work is operational, interoperability, and decision focused:

- deploy trusted issuer/key/trust-anchor configuration and replay service;
- exercise the optional envelope with a BAF-aware RDSAAD client or gateway;
- resolve the SD-008/SD-009 production ingress decision without assuming stock
  AAD/Entra clients can carry BAF assertions;
- retain and test Broker-RDP Handle while that decision remains open.

Deferred work also includes:

- production Authorization Code + PKCE front end and protected token delivery;
- broader client interoperability testing;
- cluster-wide replay, if needed;
- production configuration hardening.

The laboratory must exercise Keycloak-to-broker OIDC validation, distinct BAF
issuance, system NSS resolution, and PAM authorization. LDAP provisioning or
synchronization, SSSD, Active Directory, Kerberos, domain join, and Microsoft
Entra must not be lab or release gates.
