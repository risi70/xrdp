# BAF Reference Broker

This directory contains a broker-neutral reference broker for Phase 5
interoperability work. It proves that an external broker can issue a
BAF-compatible assertion and launch a standard RDSAAD-style connection without
adding UDS-specific behavior to XRDP core code.

The reference broker exposes the required interface:

- `create_session_assertion(user, target, broker_session_id, auth_context)`
- `list_targets(user)`
- `assign_target(user, target)`
- `launch_connection(user, target)`
- `revoke_session(broker_session_id)`

Assertions are RS256 JWT/JWS compact assertions using the existing BAF profile.
They include issuer, audience, subject, preferred Linux username, target,
broker session ID, authentication method, assurance level, issued/not-before/
expiry times, and JTI. Assertions are short-lived, target-bound,
audience-bound, and suitable for single-use replay enforcement by XRDP's trusted
replay service.

The implementation deliberately does not log raw assertions and does not carry
assertions through username or password fields. It creates the
`rdp_assertion` JSON body expected by the RDSAAD Authentication Request parser.

## UDS Reference Adapter

`uds-adapter/` is a simulator adapter. It translates UDS-like
user/session/resource objects into broker-neutral BAF users, targets, and auth
context. The adapter is not imported by `libxrdp`, `xrdp`, `sesman`,
`sesexec`, `libipm`, the validator, or the RDSAAD parser.

The simulator form is intentional for this phase. It proves the integration
boundary without baking UDS API semantics or deployment assumptions into the
generic XRDP BAF core.

## Tests

Run the Phase 5 reference broker contract test through the BAF suite:

```sh
make -C tests/baf check TESTS=test_reference_broker_contract.py
```

The test verifies valid assertion issuance, wrong audience/target rejection,
expired assertion rejection, replay rejection, unknown/unsafe/UID 0/PAM-denied
local identity rejection, RDSAAD Authentication Request creation, and UDS
adapter isolation from XRDP core code.

## Dual-Mode Phase 5 Use

Mode A uses the reference broker to issue an assertion that a native
RDSAAD-capable client carries to XRDP as `rdp_assertion`. Mode B uses the same
assertion tooling for a broker-controlled gateway, which performs RDSAAD toward
XRDP when the endpoint client cannot inject a custom assertion.

Use `issue_assertion.py` for generic RS256 assertion issuance:

```sh
python3 broker-auth/reference-broker/issue_assertion.py \
  --private-key tests/baf/data/test-private.pem \
  --kid test-key \
  --issuer https://broker.example.test \
  --audience xrdp-sesman \
  --target ubuntu-vdi-01 \
  --subject user-alice \
  --preferred-username alice \
  --broker-session-id session-123 \
  --auth-method smartcard \
  --assurance-level mfa
```

The command prints only the compact JWT/JWS by default.
