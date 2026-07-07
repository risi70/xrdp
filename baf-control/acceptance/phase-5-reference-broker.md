# Phase 5 Reference Broker and Interoperability Acceptance

## Goal

Integrate a reference broker, with UDS as the primary reference, after the generic XRDP-side BAF live path is complete.

## Scope

- UDS reference broker integration.
- Broker-neutral conformance behavior.
- Compatibility tests with standard RDP clients where feasible.
- Documentation for broker implementers.
- Optional mapping between broker authentication context and BAF claims.

## Non-goals

- Do not introduce UDS-specific assumptions into generic BAF core.
- Do not require a custom IGEL client.
- Do not bypass BAF validator, replay service, NSS/SSSD identity binding, or PAM.

## Acceptance criteria

- A reference broker can cause a standard RDP client to use the selected BAF ingress.
- XRDP validates the resulting assertion through the generic BAF path.
- Broker-specific code is isolated from generic core.
- Existing BAF security invariants remain valid.
