# RDSAAD production integration foundation

This note records the safe production insertion points for RDS AAD Auth-style BAF ingress in the current XRDP tree.

## 1. Negotiation point

`PROTOCOL_RDSAAD` is negotiated in `libxrdp/xrdp_iso.c` during X.224 connection request processing. The client advertises the bit in `RDP_NEG_REQ.requestedProtocols`; XRDP may select it in `RDP_NEG_RSP.selectedProtocol` only when broker-auth is compiled in and runtime RDSAAD configuration is complete.

When a client requests RDSAAD but runtime configuration is disabled or incomplete, negotiation fails closed. XRDP must not silently fall back to password login for that same RDSAAD-authenticated request.

## 2. Exchange insertion point

The safe hook in the current code path is in `xrdp_sec_incoming()` after `trans_set_tls_mode()` succeeds and before `xrdp_mcs_incoming()` starts MCS negotiation. At that point:

- X.224/RDP security negotiation has completed;
- TLS is established for selected non-RDP security protocols;
- MCS has not consumed the next TPKT-framed connection PDU.

This matches the required RDSAAD sequence better than placing the exchange in ISO parsing, MCS parsing, or the later window-manager/login path.

## 3. Server Nonce PDU sender

`xrdp_sec_rdsaad_exchange()` sends the Server Nonce payload after TLS is established. The payload is produced by `rdsaad_encode_server_nonce()` and sent as a TPKT-framed UTF-8 JSON message using the same transport layer that MCS would otherwise consume next.

## 4. Authentication Request receiver

`xrdp_sec_rdsaad_exchange()` receives the next TPKT-framed message with `libxrdp_force_read()` and parses the JSON payload with `rdsaad_parse_authentication_request()`.

Malformed JSON, missing `rdp_assertion`, oversized JSON, and oversized assertion payloads fail closed. Raw assertion material is cleared immediately after parsing.

## 5. Authentication Result sender

`xrdp_sec_rdsaad_exchange()` sends Authentication Result JSON with `rdsaad_encode_authentication_result()`.

The current foundation deliberately sends only failure results. It never emits `S_OK` because `S_OK` means authentication and authorization succeeded and the RDP connection may continue.

## 6. BAF validator handoff

The intended production handoff is:

`rdp_assertion` -> BAF transport -> JWT validator -> trusted replay service -> validated capability.

The parser and helper tests already prove the `rdp_assertion` value can feed `baf_transport_validate()`. The live XRDP hook currently stops before validation because a production trust/runtime configuration object and sesman/sesexec session-ready handoff are not complete.

## 7. sesman/sesexec handoff

The required production handoff is a new, clearly named BAF/RDSAAD login request that does not use username or password fields. It must create `login_info` only after:

1. assertion validation;
2. trusted replay reservation;
3. NSS/SSSD-compatible identity binding;
4. UID 0 rejection by default;
5. PAM account approval;
6. PAM credential/session lifecycle readiness.

`sesman/sesexec/eicp_server.c` currently has no such dispatch path. It accepts SYS login, UDS login, logout, and create-session only. That is the remaining live-activation blocker.

## 8. When `S_OK` may be sent

`S_OK` may be sent only after the full live broker-auth authorization path is complete and the existing XRDP session startup can proceed as the resolved Linux user. Validator success alone, replay success alone, identity binding alone, or PAM account approval alone is not sufficient.

Until the sesman/sesexec handoff exists, the RDSAAD exchange must return a controlled failure result and terminate the connection before MCS proceeds.

## 9. Classic login preservation

Classic behavior is preserved by default:

- builds without `--enable-broker-auth` have no active RDSAAD behavior;
- builds with broker-auth still leave RDSAAD disabled unless explicit runtime settings are complete;
- clients that do not request `PROTOCOL_RDSAAD` follow the existing TLS/RDP negotiation path;
- classic SYS/UDS login dispatch remains unchanged.

## 10. Tests

The current foundation is covered by:

- RDSAAD helper tests for nonce/result encoding and Authentication Request parsing;
- BAF transport/JWT validator tests for `rdp_assertion` handoff at the safe helper boundary;
- security-contract tests proving no username/password assertion overloading, no custom client/plugin dependency, no raw assertion logging, and no `S_OK` before live authorization.

Remaining tests for full activation must cover the future sesman/sesexec BAF login request, PAM denial/session failure, replay-service unavailability, and successful session startup as the resolved Linux user.
