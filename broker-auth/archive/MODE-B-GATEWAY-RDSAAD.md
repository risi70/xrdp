# Mode B - Broker Gateway RDSAAD Mode

Mode B is used when the endpoint client cannot inject a custom
`rdp_assertion`.

```text
IGEL standard RDP client
-> UDS / broker gateway
-> gateway performs RDSAAD/BAF toward XRDP
-> XRDP BAF validator
-> trusted replay service
-> NSS/SSSD
-> PAM
-> Ubuntu session
```

Mode B keeps IGEL unchanged, avoids username/password assertion overloading,
and keeps assertion generation/injection on the broker or gateway side.

## Gateway Role

The gateway is an external broker-controlled component. It receives an
authorized broker session, obtains or creates a BAF assertion, and acts as the
southbound RDSAAD-capable RDP client toward XRDP. XRDP still sees the same
RDSAAD `rdp_assertion` ingress as Mode A.

## Trust Boundaries

- Northbound broker-to-gateway calls are trusted only after broker-side
  authentication and authorization.
- The gateway must not trust endpoint-provided Linux identity.
- XRDP sesexec remains the authority for BAF validation, trusted replay,
  NSS/SSSD identity binding, UID 0 rejection, and PAM account/session
  preconditions.
- Raw assertions are credential-grade material and must not be logged.

## Northbound Broker API

The gateway receives:

- user;
- target;
- broker session ID;
- BAF assertion or broker authorization token from which the gateway can obtain
  a BAF assertion.

The broker-neutral reference interface is documented in
`broker-auth/reference-broker/protocol.md`.

## Southbound RDP/RDSAAD Client Behavior

The gateway performs the RDP client role toward XRDP:

1. negotiate `PROTOCOL_RDSAAD`;
2. receive Server Nonce;
3. send Authentication Request with `rdp_assertion`;
4. require Authentication Result `S_OK` before continuing to MCS;
5. fail closed on any Authentication Result failure.

The Phase 5 repository artifacts document this behavior and provide assertion
tooling. They do not implement a production RDP proxy.

## Assertion Lifecycle

Assertions are short-lived, target-bound, audience-bound, and single-use via
XRDP's trusted replay service. The gateway must clear assertion material after
handoff and must not persist raw assertions in logs, queues, crash dumps, or
audit records.

## Gateway Key Management

The broker or gateway signs with an RS256 private key for the current MVP.
XRDP trusts the configured public trust anchor in trusted sesman/sesexec
configuration. Test keys in this repository are not deployment keys.

## Gateway-to-XRDP TLS/mTLS Expectations

Gateway-to-XRDP transport uses normal RDP TLS. Deployments may add network
segmentation, pinned certificates, or mTLS at the gateway boundary if supported
by the deployment stack. These controls do not replace BAF assertion validation
inside XRDP.

## Audit and Logging Rules

Log non-secret metadata only, such as broker session ID, target, and result
class. Do not log raw assertions, raw tokens, private keys, or token-derived
Unix identity claims.

## Failure Handling

The gateway fails closed for missing authorization, assertion issuance failure,
XRDP RDSAAD negotiation failure, Authentication Result failure, replay service
unavailability, TLS failure, or target mismatch. It must not retry by sending
the assertion through username or password fields.

## Security Risks

- Gateway compromise can expose active assertion material.
- Mis-bound targets can create cross-host authorization failures.
- Bad logging can leak credential-grade assertions.
- Replay service outage must not degrade to process-local replay.
- Broker-side user groups must not be treated as Unix groups by XRDP.

## Production Hardening Requirements

- restrict gateway host access;
- protect signing keys with OS or HSM/KMS controls;
- pin or validate XRDP server identity;
- keep assertion lifetime short;
- isolate audit logs from raw credential material;
- monitor replay-service availability;
- include recovery and rollback runbooks.

## Non-Primary Mechanisms

CredSSP/NLA, smartcard redirection, WebAuthn redirection, and LoadBalanceInfo
are supporting or alternative mechanisms. They are not the primary BAF
assertion ingress. RDSAAD remains the XRDP-side ingress for Mode B.

The gateway must not log raw assertions. The gateway must not use username/password assertion overloading. The gateway must not require a custom IGEL client.
