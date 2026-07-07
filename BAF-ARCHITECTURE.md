# Broker Authentication Framework architecture

This branch contains an experimental Broker Authentication Framework (BAF) for XRDP.

## Goals

- Add broker-auth pre-logon support to XRDP.
- Use standard RDP-compatible mechanisms as far as possible.
- Allow IGEL OS and other clients to remain standard RDP clients.
- Support generic broker assertions without hard-coding UDS, Keycloak, or Microsoft Entra behavior.
- Preserve classic XRDP username/password PAM login.
- Preserve Linux account authority through NSS/SSSD and PAM.

## Main requirements

- Broker-auth is build-gated by `--enable-broker-auth` and disabled by default at runtime.
- RDSAAD-style ingress carries `rdp_assertion` in the RDP pre-logon exchange.
- Assertions are JWT/JWS compact assertions validated by the generic BAF provider.
- Trusted replay service is mandatory for live activation.
- Linux identity comes from NSS/SSSD-compatible lookup, not token UID/GID fields.
- UID 0 is rejected by default.
- PAM account and session lifecycle are enforced before session startup.
- No username/password assertion overloading is permitted.
- No custom IGEL client, FreeRDP plugin, dynamic virtual channel, or endpoint helper is required.
- Raw assertions are not logged.
- Ambiguous or unavailable dependencies fail closed.

## Important decisions

- SD-002 separates assertion validation from Linux identity binding.
- SD-003 splits Phase 4a prerequisites from Phase 4b live activation and requires transport-size bounds.
- SD-004 makes the trusted replay service mandatory for live activation.
- SD-005 preserves standard RDP client neutrality.
- SD-006 and SD-007 defined one-time server-side handles; they are now superseded for the MVP production ingress.
- SD-008 selects RDSAAD-style pre-logon assertion ingress as the preferred MVP path.

## High-level flow

RDSAAD negotiation -> TLS -> Server Nonce -> Authentication Request with `rdp_assertion` -> BAF validator -> trusted replay service -> NSS/SSSD identity binding -> PAM account/session lifecycle -> existing XRDP session startup as the resolved Linux user.

The current production-integration foundation proves the post-TLS/pre-MCS insertion point and fails closed. `S_OK` is withheld until the sesman/sesexec live authorization handoff is implemented.

## Security model

The assertion is credential-grade material. Validator success alone is not session authorization. Replay reservation, identity binding, UID 0 rejection, PAM account approval, and PAM session/credential lifecycle are all mandatory before a live session can start. Raw assertion bytes are cleared after handoff and are never logged.

## Current limitations and deferred work

- sesman/sesexec BAF login handoff from RDSAAD-authenticated XRDP is still deferred.
- Full live session activation remains deferred until that handoff is safe.
- UDS reference broker integration remains Phase 5 work.
- Broader client interoperability testing remains Phase 5 work.
- Optional Microsoft/Entra-specific validation can be added later only as isolated deployment policy.
- Cluster-wide replay and production configuration hardening remain future work.
