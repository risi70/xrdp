# Broker Authentication Framework architecture

This branch contains an experimental Broker Authentication Framework (BAF) for
XRDP.

BAF adds broker-authenticated pre-logon support while preserving the existing
XRDP username/password PAM path. The current implementation is intentionally
conservative: RDSAAD-style ingress is scaffolded and fails closed until the
sesman/sesexec session-ready handoff is implemented.

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
- SD-006 and SD-007 defined one-time server-side handles. They are now
  superseded for the MVP production ingress.
- SD-008 selects RDSAAD-style pre-logon assertion ingress as the preferred MVP
  path.

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

The current production-integration foundation parses the RDSAAD Authentication
Request and clears `rdp_assertion`, but it deliberately returns controlled
failure. It does not emit `S_OK`, does not continue to MCS, and does not start a
session.

## Current Limitations / Deferred Work

Full live RDSAAD activation remains deferred. The missing abstraction is a
production BAF/RDSAAD login handoff that can create a session-ready
`login_info` from a fully authorized BAF result without using username/password
fields and without trusting client-provided UID/GID material.

That handoff must define:

- the SCP/EICP request and response shape for BAF/RDSAAD login;
- where live assertion validation runs;
- how trusted replay service configuration is supplied;
- how the resolved Linux username and PAM state become `login_info`;
- how failures return Authentication Result failure without password fallback;
- how classic SYS/UDS login dispatch remains unchanged.

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
