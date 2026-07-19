# SD-008 — RDS AAD Auth-style pre-logon assertion ingress

## Decision

BAF uses an RDS AAD Auth-style RDP pre-logon assertion exchange as the preferred MVP ingress mechanism for broker-auth assertions. The mechanism is based on Microsoft Open Specifications [MS-RDPBCGR] sections 5.4.5.4.1, 2.2.18.1, 2.2.18.2, 2.2.18.2.1, 2.2.18.3, and 4.11.

`PROTOCOL_RDSAAD`-style negotiation is the preferred standard-compatible mechanism. After negotiation and TLS establishment, the server sends a Server Nonce PDU, the client sends an Authentication Request PDU, and the Authentication Request carries a JSON `rdp_assertion` member. For BAF, that `rdp_assertion` value is a compact JWT/JWS BAF assertion validated by the existing generic BAF JWT provider. The server returns an Authentication Result PDU containing a Microsoft-compatible HRESULT status.

This replaces the one-time server-side assertion-handle ingress design as the preferred MVP path. SD-006 and SD-007 handle semantics remain valid only for experimental/fallback/test code unless a future decision reselects them. One-time assertion handles are no longer the production MVP ingress mechanism.

Username/password assertion overloading remains forbidden. Custom IGEL client/plugin behavior remains forbidden. UDS-specific and Keycloak-specific behavior remain deferred to Phase 5. The trusted replay service remains mandatory for live broker-auth activation. NSS/SSSD identity binding and PAM preconditions remain as implemented in Phase 4a.

## Microsoft protocol mapping

- Security negotiation uses `PROTOCOL_RDSAAD` (`0x00000010`) in the `requestedProtocols` field of `RDP_NEG_REQ`; a supporting server selects it in `RDP_NEG_RSP.selectedProtocol`.
- The Server Nonce PDU is a UTF-8 JSON string of the form `{"ts_nonce":"<nonce_value>"}`.
- The Authentication Request PDU is a UTF-8 JSON string of the form `{"rdp_assertion":"<rdp_assertion_value>"}`.
- The RDP Assertion is a JWS Compact Serialization JWT. BAF validates the compact assertion with the BAF JWT profile rather than hard-coding Microsoft Entra validation.
- The Authentication Result PDU is a UTF-8 JSON string of the form `{"authentication_result":"<error_code>"}` where the error code is a 32-bit HRESULT. `S_OK` means authentication and authorization succeeded and the RDP connection can proceed.

Because `S_OK` means the connection can proceed, BAF MUST NOT send a success result until the live authorization path is complete. Protocol scaffolding MAY parse and validate `rdp_assertion` and return controlled failure while live activation remains deferred.

## Consequences

XRDP must parse and process RDS AAD Auth-style Authentication Request/Result PDUs. BAF assertion ingress occurs inside the RDP protocol, not through routing-token handles. Standard IGEL/RDP clients that support the Microsoft mechanism should be usable without custom endpoint code.

Microsoft/Entra-specific validation is not required unless explicitly configured; the generic BAF JWT profile remains broker-neutral. CloudAP/LSA specifics are Windows implementation details; the XRDP equivalent is BAF validator, trusted replay service, NSS/SSSD identity binding, PAM preconditions, and then session authorization.

## Non-goals

- no username/password assertion overloading;
- no custom IGEL client;
- no FreeRDP plugin requirement;
- no dynamic virtual channel requirement;
- no endpoint-side BAF helper;
- no UDS-specific implementation in Phase 4b;
- no Keycloak-specific implementation in Phase 4b;
- no generic reusable out-of-band handles;
- no full JWT in routing/preconnection metadata.
