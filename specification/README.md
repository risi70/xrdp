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

## Conformance

An implementation claiming BAF 1.0 conformance MUST implement the assertion
profile, validation order, replay semantics, target binding, identity mapping,
PAM account/session lifecycle, protocol capability negotiation, and required
tests. Supporting the reference broker is neither necessary nor sufficient.

## Decision summary

- XRDP transports the original assertion; sesexec validates it locally.
- Compact asymmetric JWS is used; RS256 is mandatory for interoperability.
- NSS/SSSD remains the authority mapping names to Linux UIDs.
- PAM authentication is skipped only for a locally validated assertion.
- PAM account, credentials, session, environment, and cleanup remain mandatory.
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
