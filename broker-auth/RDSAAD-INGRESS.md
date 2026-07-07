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

The Authentication Result `S_OK` value means authentication and authorization succeeded and the RDP connection can proceed. The pre-MCS bridge returns `S_OK` only after sesman/xrdp-sesexec completes the full BAF preauth chain and creates session-ready login state.

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

- deploy trusted local BrokerAuth configuration and replay service in target environments;
- broker/client interoperability testing with an RDSAAD-capable client;
- Phase 5 UDS reference broker integration;
- optional Microsoft/Entra-specific validation if ever required by deployment policy.

## Production integration foundation

The first production hook is now identified in `xrdp_sec_incoming()`: after TLS has been established for selected `PROTOCOL_RDSAAD`, and before MCS negotiation consumes the next connection PDU. This allows XRDP to send the Server Nonce JSON, receive the Authentication Request JSON, and send an Authentication Result before MCS proceeds.

The hook is runtime gated. RDSAAD remains disabled by default and is selected only when broker-auth RDSAAD settings are explicitly enabled and complete. If RDSAAD is requested without valid runtime configuration, negotiation fails closed.

The pre-MCS bridge now delegates authorization through the xrdp owner callback to sesman and xrdp-sesexec. `S_OK` is emitted only after the full BAF chain produces session-ready authorization state and the authenticated sesman transport is bound to the current connection. See `RDSAAD-INTEGRATION-FOUNDATION.md` and `RDSAAD-PREMCS-BRIDGE.md`.
