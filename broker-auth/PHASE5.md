# Phase 5 - Reference Broker and Interoperability

## Implemented

Phase 5 adds a broker-neutral reference broker under
`broker-auth/reference-broker/`.

The reference broker implements:

- `create_session_assertion(user, target, broker_session_id, auth_context)`;
- `list_targets(user)`;
- `assign_target(user, target)`;
- `launch_connection(user, target)`;
- `revoke_session(broker_session_id)`.

It issues BAF-compatible RS256 JWT/JWS assertions using the existing reference
issuer and assertion schema. Assertions are short-lived, target-bound,
audience-bound, contain `jti` for replay enforcement, and are carried in the
RDSAAD Authentication Request `rdp_assertion` field.

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

## Deferred

- Production UDS API adapter implementation.
- JWKS rotation service for the reference broker.
- Full external wire-level RDSAAD client automation.
- Cluster-wide replay policy.
- Production packaging and operational hardening.
