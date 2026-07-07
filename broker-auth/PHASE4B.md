# Phase 4b: Live Broker-Auth Session Activation

## Scope

Phase 4b is the next implementation phase. SD-008 changes the preferred MVP
ingress from handle-first SCP/EICP transport to RDS AAD Auth-style pre-logon
RDP assertion ingress. Phase 4b still connects validated broker assertions and
the completed Phase 4a authorization prerequisites to the existing XRDP login
and session lifecycle. A broker login may become
session-authorized only after a valid assertion, atomic replay reservation,
validated capability, NSS/SSSD-resolved identity, default UID 0 rejection, and
PAM account approval. PAM credentials, session open/close, environment, and
cleanup continue through XRDP's existing session path.

## Prerequisites

- Phases 1–3 and Phase 4a are complete.
- Runtime broker configuration is valid and explicitly enables broker auth.
- Classic SCP/EICP password messages remain byte-compatible.
- The exact assertion payload capacity after SCP/EICP framing is calculated and
  enforced at every hop.
- A persistent trusted replay service is reachable over its restricted local
  Unix-domain socket. Live workers never fall back to process-local replay.

## Transport-size rule

The effective maximum is the minimum of the configured validator maximum, the
configured transport maximum, and libipm/SCP/EICP payload capacity after
framing overhead. The nominal MVP in-band transport ceiling is 8 KiB; usable
assertion bytes are necessarily lower. Oversize assertions fail closed before
allocation or validation where possible. Phase 4b implements no fragmentation,
no username/password assertion overloading, no custom client/plugin transport,
and no generic out-of-band assertion handles. SD-008 RDSAAD-style
`rdp_assertion` is the selected MVP ingress; SD-006 handles are superseded for
production ingress.

## Acceptance criteria

- Live authorization requires every BAF validation, replay, identity, and PAM
  precondition; no intermediate success can start a session.
- Broker auth is disabled by default at build time and runtime.
- Classic password/PAM behavior is unchanged.
- Boundary tests cover exact permitted size and one byte over.
- Dynamic PAM tests prove account denial, session-open failure, absence of
  `pam_authenticate()` on broker login, and its continued use on classic login.
- Replay remains consumed after identity, PAM, or session failure.
- Raw assertions are erased and never logged.

## Non-goals

- UDS-specific or Keycloak-specific XRDP logic.
- Fragmentation, reassembly, username/password assertion overloading, custom client/plugin transport, or generic out-of-band assertion handles. SD-008 RDSAAD-style pre-logon ingress is the selected MVP path; SD-006 handles are experimental/fallback only.
- Direct LDAP, FreeIPA, Active Directory, or SSSD APIs.
- Enabling broker auth by default.
- Trusting assertion UID, GID, or groups as Linux authorization data.
- Cluster-wide replay coordination or persistent replay-service storage.

## Phase 4b ingress replacement

SD-008 supersedes handle-first ingress. The preferred MVP path is now RDS AAD Auth-style pre-logon assertion ingress: `PROTOCOL_RDSAAD` negotiation, Server Nonce PDU, Authentication Request PDU carrying `rdp_assertion`, BAF validation, trusted replay, and Authentication Result PDU. The current safe implementation boundary is protocol/validation scaffolding; `S_OK` must not be sent until live authorization and session activation are complete. SD-006/SD-007 handle code may remain as experimental/fallback/test code but is not the production MVP ingress.

## RDSAAD production integration foundation

The safe production insertion point is post-TLS and pre-MCS in `xrdp_sec_incoming()`. `PROTOCOL_RDSAAD` negotiation is runtime-gated and disabled by default. When selected, XRDP can perform the Server Nonce / Authentication Request / Authentication Result exchange before MCS starts.

This foundation does not send `S_OK`. The RDSAAD exchange fails closed after parsing because a production sesman/sesexec BAF login handoff has not yet created a session-ready `login_info` from the validated assertion, trusted replay reservation, NSS identity, UID 0 rejection, and PAM account/session lifecycle. Classic SYS/UDS login remains unchanged.

Handle ingress remains superseded by SD-008 but is retained as experimental/test code until the RDSAAD live path fully replaces it.
