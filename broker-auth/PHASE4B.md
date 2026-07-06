# Phase 4b: Live Broker-Auth Session Activation

## Scope

Phase 4b is the next implementation phase. It connects the Phase 3 opaque
SCP/EICP transport and the completed Phase 4a authorization prerequisites to
the existing XRDP login and session lifecycle. A broker login may become
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
allocation or validation where possible. Phase 4b implements neither
fragmentation nor out-of-band assertion handles.

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
- Fragmentation, reassembly, or out-of-band assertion handles.
- Direct LDAP, FreeIPA, Active Directory, or SSSD APIs.
- Enabling broker auth by default.
- Trusting assertion UID, GID, or groups as Linux authorization data.
- Cluster-wide replay coordination or persistent replay-service storage.

## Phase 4b-1 handle ingress

SD-006 permits a standard broker-compatible opaque handle while retaining the full assertion in `xrdp-baf-handled`. Handle resolution is atomic and feeds the existing BAF transport/validator path. The resulting state is `BAF_HANDLE_VALIDATED_NOT_SESSION_AUTHORIZED`: neither resolution nor validation authorizes login. Identity binding, PAM, and live session startup remain Phase 4b-2.
