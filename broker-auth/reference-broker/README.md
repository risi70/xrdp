# BAF Reference Broker

This directory contains a broker-neutral reference broker for Phase 5
interoperability work. Keycloak is the primary user-facing IdP in the target
architecture: the broker validates Keycloak/OIDC and issues a distinct
BAF-compatible assertion without adding IdP- or UDS-specific behavior to XRDP
core code. `keycloak_auth.py` implements the isolated broker-side verification
and policy adapter used by the reference implementation.

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

Run the Phase 5 reference broker and Keycloak contract tests through the BAF
suite:

```sh
make -C tests/baf check TESTS=test_phase5_dual_mode_contract.py
```

The test verifies valid assertion issuance, wrong audience/target rejection,
expired assertion rejection, replay rejection, unknown/unsafe/UID 0/PAM-denied
local identity rejection, RDSAAD Authentication Request creation, and UDS
adapter isolation from XRDP core code.

## Keycloak IdP

`keycloak_auth.py` validates Keycloak access tokens against the realm's
configured JWKS endpoint. Issuer, audience, authorized party, token type,
algorithm, lifetime, token size, claim types, claim counts, and claim lengths
fail closed. HTTPS is mandatory outside unit tests.

The `KeycloakBrokerAdapter` binds issuer and subject into one broker identity,
requires a configured client-scoped desktop role, maps to an existing broker
user, and checks a per-user target allowlist before BAF issuance. Keycloak
groups and roles are not treated as Linux groups. The adapter accepts an
already obtained access token; an external broker front end remains responsible
for Authorization Code flow, PKCE, state, nonce, redirect URI, and protected
token delivery.

## Optional RDSAAD Use

A BAF-aware RDSAAD client can carry the assertion to XRDP as `rdp_assertion`, or
a broker-controlled gateway can perform RDSAAD toward XRDP. This optional
MS-RDPBCGR-compatible envelope does not provide Microsoft identity integration
or stock AAD/Entra-client compatibility. Broker-RDP Handle remains included and
the SD-008/proposed-SD-009 production choice is unresolved.

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
  --auth-method oidc,mfa \
  --assurance-level mfa
```

The command prints only the compact JWT/JWS by default.
