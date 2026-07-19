# Phase 5 - Reference Broker and Interoperability

## Implemented

Phase 5 contains broker-neutral assertion tooling and two optional RDSAAD
interoperability roles:

- Mode A: BAF-aware RDSAAD client;
- Mode B: broker gateway RDSAAD.

RDSAAD is an optional MS-RDPBCGR-compatible envelope for both roles. It does not
provide Microsoft identity integration or compatibility with stock AAD/Entra
clients. XRDP core remains broker-neutral. Broker-RDP Handle remains included,
and production selection between SD-008 and proposed SD-009 is unresolved.

CredSSP/NLA, smartcard redirection, WebAuthn redirection, and LoadBalanceInfo
are supporting or alternative mechanisms, not the primary BAF assertion ingress.

Phase 5 adds a broker-neutral reference broker under
`broker-auth/reference-broker/`.

The reference broker includes a Keycloak OIDC verifier and policy adapter. It
validates a Keycloak token at the broker boundary, maps it to a configured
broker user, requires desktop authorization, and only then issues the distinct
BAF assertion.

The reference broker implements:

- `create_session_assertion(user, target, broker_session_id, auth_context)`;
- `list_targets(user)`;
- `assign_target(user, target)`;
- `launch_connection(user, target)`;
- `revoke_session(broker_session_id)`.

It issues BAF-compatible RS256 JWT/JWS assertions using the existing reference
issuer and assertion schema. Assertions are short-lived, target-bound,
audience-bound, and contain `jti` for replay enforcement. An enabled ingress
transports or resolves them; optional RDSAAD uses the Authentication Request
`rdp_assertion` field.

The UDS reference integration is a simulator adapter in
`broker-auth/reference-broker/uds-adapter/`. It maps UDS-like
user/session/resource objects into broker-neutral BAF users, targets, and auth
context. It is not imported by XRDP core code.

## Tests

`tests/baf/test_reference_broker_contract.py` covers:

- valid assertion issuance and conformance verification;
- wrong audience rejection;
- wrong target rejection;
- expired assertion rejection;
- replay rejection by the reference replay ledger;
- unknown local user rejection;
- unsafe username rejection;
- UID 0 rejection;
- PAM-denied user rejection;
- RDSAAD Authentication Request creation with no password field;
- UDS simulator adapter isolation from XRDP core.

Run:

```sh
make -C tests/baf check TESTS=test_reference_broker_contract.py
```

or the full BAF suite:

```sh
make -C tests/baf check
```

## Isolation Rules

UDS-specific behavior remains outside:

- `libxrdp`;
- `xrdp`;
- `sesman`;
- `sesexec`;
- `libipm`;
- BAF validator;
- RDSAAD parser.

No username/password assertion overloading, custom IGEL client, FreeRDP plugin,
dynamic virtual channel, raw assertion logging, token UID/GID trust, or token
group-to-Unix-group trust is introduced.

Keycloak is the primary user-facing IdP. The production broker validates
Keycloak/OIDC and issues a distinct BAF assertion. XRDP validates only BAF and
resolves the Linux identity through system NSS before PAM. LDAP provisioning or
synchronization, SSSD configuration or availability, Active Directory,
Kerberos, domain join, and Microsoft Entra are not Phase 5 prerequisites.

## Deferred

- Production Authorization Code + PKCE front end and protected token delivery.
- JWKS rotation service for the reference broker.
- Full external wire-level RDSAAD client automation.
- Optional Mode A proof with a BAF-aware client.
- Mode B production gateway implementation.
- Cluster-wide replay policy.
- Production packaging and operational hardening.

## Phase 6 Handoff

Phase 5 broker-neutral artifacts can be consumed by a KVM lab while keeping
XRDP core broker-neutral. The lab must validate the Keycloak-to-broker OIDC
boundary, distinct BAF issuance, trusted replay, system NSS, and PAM. Optional
UDS adapters and RDSAAD wire clients are not lab or release prerequisites.
