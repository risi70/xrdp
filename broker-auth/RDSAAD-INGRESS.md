# RDSAAD-style pre-logon assertion ingress

Phase 4b now prefers an RDS AAD Auth-style pre-logon assertion exchange for BAF ingress. The design follows the Microsoft RDP mechanism documented in [MS-RDPBCGR] sections 5.4.5.4.1, 2.2.18.1, 2.2.18.2, 2.2.18.2.1, 2.2.18.3, and 4.11.

Implementation note:

1. The client requests `PROTOCOL_RDSAAD` (`0x00000010`) in `RDP_NEG_REQ.requestedProtocols`.
2. The server selects `PROTOCOL_RDSAAD` in `RDP_NEG_RSP.selectedProtocol` only when broker-auth RDSAAD mode is explicitly enabled.
3. TLS is established before the assertion exchange.
4. The server sends a Server Nonce PDU containing UTF-8 JSON: `{"ts_nonce":"<nonce>"}`.
5. The client sends an Authentication Request PDU containing UTF-8 JSON: `{"rdp_assertion":"<compact-jws>"}`.
6. XRDP extracts `rdp_assertion` and passes it to the existing BAF transport/JWT validator path.
7. The validator reserves replay through the trusted replay service before live activation.
8. The server sends an Authentication Result PDU containing UTF-8 JSON: `{"authentication_result":"<HRESULT>"}`.

The Authentication Result `S_OK` value means authentication and authorization succeeded and the RDP connection can proceed. Until Phase 4b live activation is proven end-to-end, scaffolding may validate the assertion but must not return false success.

The `rdp_assertion` field carries the BAF compact JWT/JWS assertion. It is broker-neutral: XRDP validates the configured BAF issuer/audience/target/trust profile and does not hard-code Microsoft Entra, Keycloak, UDS, or any IdP-specific behavior.

This preserves standard client neutrality. It requires no custom IGEL client, no IGEL helper, no FreeRDP plugin, no dynamic virtual channel, no username/password assertion overloading, and no endpoint-side BAF-specific helper. Clients that implement the Microsoft RDSAAD-style mechanism can carry the assertion through the RDP protocol itself.

One-time server-side assertion handles from SD-006/SD-007 are superseded as the selected MVP ingress. The handle service may remain as experimental/fallback/test code, but production Phase 4b ingress must not depend on it unless a later decision reselects it. Generic out-of-band bearer handles remain forbidden.

Failure behavior:

- malformed RDSAAD PDU or JSON maps to `SEC_E_INVALID_TOKEN`;
- missing or oversized `rdp_assertion` maps to `SEC_E_INVALID_TOKEN`;
- invalid signature, expiry, audience, target, or replay maps to `SEC_E_INVALID_TOKEN` or `E_ACCESSDENIED` according to the authentication boundary;
- replay-service unavailable maps to a security/internal failure such as `STATUS_NO_LOGON_SERVERS`;
- identity/PAM denial maps to `E_ACCESSDENIED` or a more specific MS-ERREF status.

Remaining deferred work:

- exact XRDP insertion point for the post-TLS/pre-MCS RDSAAD PDU exchange;
- runtime configuration for enabling RDSAAD mode and BAF trust parameters;
- full live session activation;
- Phase 5 UDS reference broker integration;
- broker interoperability testing;
- optional Microsoft/Entra-specific validation if ever required by deployment policy.
