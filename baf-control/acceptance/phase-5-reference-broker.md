# Phase 5 Reference Broker and Interoperability Acceptance

## Goal

Integrate a broker-neutral reference broker after the generic XRDP-side BAF
live path is complete. Keycloak is the primary user-facing IdP; the broker
validates Keycloak/OIDC and issues a distinct BAF assertion.

## Scope

- Keycloak/OIDC authentication-context validation at the broker boundary.
- Broker-neutral conformance behavior.
- Compatibility tests with standard RDP clients where feasible.
- Documentation for broker implementers.
- Optional mapping between broker authentication context and BAF claims.
- Optional isolated UDS adapter coverage.

## Non-goals

- Do not introduce UDS-specific assumptions into generic BAF core.
- Do not require a custom IGEL client.
- Do not pass Keycloak tokens to XRDP or make XRDP validate OIDC tokens.
- Do not bypass BAF validator, replay service, system NSS identity binding, or PAM.
- Do not require LDAP provisioning/synchronization, SSSD, Active Directory, Kerberos, domain join, or Microsoft Entra.

## Acceptance criteria

- A reference broker can issue a distinct broker-neutral BAF assertion for an authorized Keycloak/OIDC session.
- Keycloak token validation binds issuer, audience/client, authorized party,
  algorithm, lifetime, subject, username, and bounded authentication context.
- A valid Keycloak token does not bypass broker user, role, or target policy.
- At least one enabled BAF ingress can transport or resolve that assertion; acceptance does not select between SD-008 and proposed SD-009.
- XRDP validates the resulting assertion through the generic BAF path.
- RDSAAD tests use a BAF-aware client or gateway and do not claim stock Entra-client compatibility.
- Broker-specific code is isolated from generic core.
- Existing BAF security invariants remain valid.
