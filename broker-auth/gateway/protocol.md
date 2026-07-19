# Gateway Protocol Skeleton

The Phase 5 gateway protocol is a broker-to-gateway control contract. It is not
an XRDP core protocol and is not SCP/EICP.

## Northbound Request

The gateway receives:

- `user`;
- `target`;
- `broker_session_id`;
- either a BAF assertion or a broker authorization token that can be exchanged
  for a BAF assertion;
- optional auth context metadata.

The gateway must treat assertion material as credential-grade data.
Keycloak/OIDC tokens terminate at the broker and must not be forwarded to XRDP
as BAF assertions.

## Southbound RDSAAD

Toward XRDP, the gateway behaves as an RDSAAD-capable RDP client:

```text
connect to XRDP
-> negotiate PROTOCOL_RDSAAD
-> receive Server Nonce
-> send Authentication Request with rdp_assertion
-> require Authentication Result S_OK
-> continue to MCS only after S_OK
```

## Response

The gateway returns only structured result metadata:

- success/failure;
- target;
- broker session ID;
- non-secret failure class.

It must not return raw assertion material in logs or audit records.

This gateway control contract is not SCP/EICP.
No username/password assertion transport is allowed.
This optional southbound role does not select SD-008 over Broker-RDP Handle or
proposed SD-009 and does not imply stock AAD/Entra-client compatibility.
