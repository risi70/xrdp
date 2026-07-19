# Generic Broker Authentication Framework Specification

**Version 1.0 — Contractual baseline**

This directory specifies a broker-independent authentication extension for
XRDP. Implementations conform only when they satisfy the normative requirements
in all ten documents and the referenced test gates.

1. [System architecture](01-system-architecture.md)
2. [Broker assertion specification](02-broker-auth-specification.md)
3. [Security model](03-security-model.md)
4. [XRDP extension specification](04-xrdp-extension-specification.md)
5. [Configuration model](05-configuration-model.md)
6. [API and protocol specification](06-api-and-protocol-specification.md)
7. [Testing strategy](07-testing-strategy.md)
8. [Docker/KVM test laboratory](08-docker-kvm-test-lab.md)
9. [CI/CD strategy](09-ci-cd-strategy.md)
10. [Development roadmap](10-roadmap.md)

Normative decisions:

- [SD-002 — Separation of Assertion Validation and Linux Identity Binding](decisions/SD-002-validation-identity-separation.md)
- [SD-003 — Phase Ownership and Assertion Transport Size](decisions/SD-003-phase-ownership-transport-size.md)
- [SD-004 — Trusted Replay Service for Live Broker Authentication](decisions/SD-004-trusted-replay-service.md)
- [SD-006 — One-time Server-side Assertion Handles](decisions/SD-006-one-time-server-side-assertion-handles.md)
- [SD-007 — Target-mismatched Handle Resolution Consumes the Handle](decisions/SD-007-target-mismatch-consumes-handle.md)
- [SD-008 — RDS AAD Auth-style Pre-logon Assertion Ingress](decisions/SD-008-rdsaad-style-prelogon-assertion-ingress.md)
- [SD-009 — Robust Ingress Tracks and Buildable Missing Components (Broker-RDP Handle — shipped)](decisions/SD-009-robust-ingress-tracks.md)

## Conformance

An implementation claiming BAF 1.0 conformance MUST implement the assertion
profile, validation order, replay semantics, target binding, identity mapping,
PAM account/session lifecycle, protocol capability negotiation, and required
tests. BAF conformance separates assertion validation, transport, mandatory
Linux identity binding, PAM preconditions, and live session activation. A
validated broker capability alone is never sufficient to authorize or launch a
session. Phase 4a is the completed identity/PAM-precondition phase; Phase 4b
owns live broker-auth activation; Phase 5 remains reference broker and
interoperability work. Supporting UDS Enterprise or any other reference broker
is neither necessary nor sufficient for core BAF conformance.

## Decision summary

- XRDP transports the original assertion; sesexec validates it locally.
- Phase 2 uses compact JWS with exact RS256; PS256/ES256 are future extensions.
- Assertion validation performs no local or directory identity lookup.
- NSS/SSSD remains the mandatory authority mapping names to Linux UIDs before
  PAM account/session processing and session creation.
- A validated broker capability alone never authorizes or launches a session.
- PAM authentication may be skipped only after both local assertion validation
  and mandatory Phase 4a Linux identity binding; a capability alone is
  insufficient.
- PAM account, credentials, session, environment, and cleanup remain mandatory.
- Phase 4a produces no live-session authorization; Phase 4b owns activation
  after every validation, replay, identity, UID, and PAM prerequisite passes.
- Phase 4b replay reservation is host-local and cross-process through the
  trusted replay service; worker-local memory replay remains test-only and
  service failure denies broker authentication without affecting classic PAM.
- The validator's 16 KiB default is an upper validation bound. In-band SCP/EICP
  transport has a nominal 8 KiB message ceiling and MUST subtract framing
  overhead; the effective maximum is the minimum of validator, transport, and
  available payload limits.
- SD-008 selects RDS AAD Auth-style pre-logon assertion ingress as the preferred MVP ingress. The assertion enters through RDP protocol `rdp_assertion` material, not username/password fields, routing-token handles, custom plugins, or dynamic virtual channels. SD-006/SD-007 one-time handles are superseded for production MVP ingress and may remain only experimental/fallback/test code. The MVP still has no fragmentation and no generic out-of-band bearer handles.
- Classic password/PAM login remains default and wire-compatible.
- Keycloak is a possible broker IdP, not an XRDP dependency.
- No UDS Enterprise concept appears in the XRDP extension contract.

## Normative references

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
- [RFC 7515 — JWS](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7518 — JWA](https://www.rfc-editor.org/rfc/rfc7518)
- [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- OpenID Connect Core 1.0
- Linux-PAM, SSSD, systemd, OpenSSL, and current upstream XRDP documentation
