# Optional RDSAAD integration foundation

This note records the safe insertion points for the optional RDS AAD Auth-style
BAF assertion envelope in the current XRDP tree. It implements the relevant
MS-RDPBCGR wire shape, not Microsoft identity integration. Stock AAD/Entra
clients do not emit BAF assertions. Broker-RDP Handle remains included and the
SD-008/proposed-SD-009 production ingress choice is unresolved.

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

`xrdp_sec_rdsaad_exchange()` sends Authentication Result JSON with
`rdsaad_encode_authentication_result()`.

`S_OK` is emitted only when the libxrdp owner callback returns
`XRDP_RDSAAD_PREAUTH_AUTHORIZED`. That callback result is produced only after
sesman and xrdp-sesexec complete the BAF preauth chain and create session-ready
login state. Parser errors, validation errors, replay failures, identity/PAM
failures, service unavailability, or missing live configuration return failure
HRESULTs and stop the connection before MCS.

## 6. BAF validator handoff

The production handoff is:

`rdp_assertion` -> libxrdp owner callback -> xrdp SCP broker preauth request ->
sesman dispatch -> EICP broker preauth request -> xrdp-sesexec BAF transport ->
JWT validator -> trusted replay service -> validated capability -> system NSS
identity binding -> UID 0 rejection -> PAM broker preconditions ->
session-ready `login_info`.

Raw assertion bytes are bounded, never logged, erased after handoff/validation,
and are not stored in xrdp, sesman, sesexec, or `login_info`.

## 7. sesman/sesexec handoff

The bridge uses the existing broker login request codecs
`E_SCP_BROKER_LOGIN_REQUEST_V1` and `E_EICP_BROKER_LOGIN_REQUEST_V1`; they carry
bounded assertion material and metadata and do not overload classic credentials.
The bridge does not use username or password fields. `sesman` validates
trusted live BAF configuration, starts xrdp-sesexec, forwards the request, and
marks successful connections as `E_SLI_LOGIN_BAF`.

`xrdp-sesexec` owns live validation and authorization. It loads trusted
[BrokerAuth] configuration from local sesman config, requires service-backed
replay, binds identity through system NSS APIs, rejects UID 0 by
default, runs broker PAM account/session preconditions without
`pam_authenticate()`, and creates `login_info` for the resolved Linux username.

## 8. When `S_OK` may be sent

`S_OK` may be sent only after the full broker-auth authorization path is complete
and the authenticated sesman transport is bound to the current xrdp process for
post-MCS session startup. Validator success alone, replay success alone,
identity binding alone, or PAM account approval alone is not sufficient.

## 9. Classic login preservation

Classic behavior is preserved by default:

- builds without `--enable-broker-auth` have no active RDSAAD behavior;
- builds with broker-auth still leave RDSAAD disabled unless explicit runtime settings are complete;
- clients that do not request `PROTOCOL_RDSAAD` follow the existing TLS/RDP negotiation path;
- classic SYS/UDS login dispatch remains unchanged.

## 10. Tests

The pre-MCS bridge foundation is covered by:

- RDSAAD helper tests for nonce/result encoding and Authentication Request parsing;
- BAF transport/JWT validator tests for `rdp_assertion` handoff at the safe helper boundary;
- security-contract tests proving no username/password assertion overloading, no custom client/plugin dependency, no raw assertion logging, and no `S_OK` before live authorization.

Remaining tests for full activation must cover the future sesman/sesexec BAF login request, PAM denial/session failure, replay-service unavailability, and successful session startup as the resolved Linux user.
