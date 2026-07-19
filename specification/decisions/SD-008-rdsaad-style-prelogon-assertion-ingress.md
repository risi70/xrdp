# SD-008 — RDS AAD Auth-style pre-logon assertion ingress

**Status:** Accepted protocol design; production ingress selection remains
unresolved with proposed SD-009.

## Decision

BAF may use an RDS AAD Auth-style RDP pre-logon assertion exchange as an optional
broker-auth assertion envelope. The mechanism is based on Microsoft Open
Specifications [MS-RDPBCGR] sections 5.4.5.4.1, 2.2.18.1, 2.2.18.2,
2.2.18.2.1, 2.2.18.3, and 4.11. This decision does not select the production
ingress over the Broker-RDP Handle tracks proposed by SD-009.

After optional `PROTOCOL_RDSAAD`-style negotiation and TLS establishment, the
server sends a Server Nonce PDU, the client sends an Authentication Request PDU,
and the Authentication Request carries a JSON `rdp_assertion` member. For BAF,
that value is a compact JWT/JWS BAF assertion validated by the generic BAF JWT
provider. The server returns an Authentication Result PDU containing an
MS-RDPBCGR-compatible HRESULT status.

SD-006 and SD-007 one-time server-side handle semantics remain valid and
Broker-RDP Handle remains included. Proposed SD-009 challenges this decision's
former ingress preference; no final choice between the ingress designs is made
here.

Username/password assertion overloading remains forbidden. Custom IGEL
client/plugin behavior cannot be required. Keycloak is the primary user-facing
IdP, but the broker validates Keycloak/OIDC and issues a distinct BAF assertion;
XRDP does not validate Keycloak tokens. The trusted replay service, system NSS
identity binding, and PAM preconditions remain mandatory for live broker-auth.

## Microsoft protocol mapping

- Security negotiation uses `PROTOCOL_RDSAAD` (`0x00000010`) in the `requestedProtocols` field of `RDP_NEG_REQ`; a supporting server selects it in `RDP_NEG_RSP.selectedProtocol`.
- The Server Nonce PDU is a UTF-8 JSON string of the form `{"ts_nonce":"<nonce_value>"}`.
- The Authentication Request PDU is a UTF-8 JSON string of the form `{"rdp_assertion":"<rdp_assertion_value>"}`.
- The RDP Assertion is a JWS Compact Serialization JWT. BAF validates the compact assertion with the BAF JWT profile and performs no Microsoft identity validation.
- The Authentication Result PDU is a UTF-8 JSON string of the form `{"authentication_result":"<error_code>"}` where the error code is a 32-bit HRESULT. `S_OK` means authentication and authorization succeeded and the RDP connection can proceed.

Because `S_OK` means the connection can proceed, BAF MUST NOT send a success result until the live authorization path is complete. Protocol scaffolding MAY parse and validate `rdp_assertion` and return controlled failure while live activation remains deferred.

## Consequences

When enabled, XRDP parses and processes the RDS AAD Auth-style Authentication
Request/Result PDUs as an assertion envelope. A BAF-aware client or gateway must
place a BAF assertion in `rdp_assertion`. Stock AAD/Entra clients produce a
different assertion profile and are not compatible merely because they support
the Microsoft mechanism.

The generic BAF JWT profile remains broker-neutral. Microsoft identity
integration and stock Entra-client compatibility are out of scope. XRDP's chain
is BAF validation, trusted replay, system NSS identity binding, PAM
preconditions, and then session authorization.

## Non-goals

- no username/password assertion overloading;
- no custom IGEL client;
- no FreeRDP plugin requirement;
- no dynamic virtual channel requirement;
- no endpoint-side BAF helper;
- no UDS-specific implementation in Phase 4b;
- no Keycloak-specific implementation in Phase 4b;
- no Microsoft identity integration or stock Entra-client compatibility;
- no generic reusable out-of-band handles;
- no full JWT in routing/preconnection metadata.
