# Phase 4b Bridge Acceptance

## Goal

Bridge RDSAAD pre-logon assertion authorization from libxrdp into xrdp/sesman/sesexec safely, without custom client behavior and without username/password assertion overloading.

## Required deliverables

- libxrdp-to-xrdp RDSAAD authorization callback or equivalent safe bridge.
- Dedicated SCP/EICP BAF/RDSAAD login request dispatch, or equivalent explicitly named request path.
- BAF-capable `login_info` or equivalent session-ready authorization object.
- Trusted replay service enforcement for live activation.
- NSS/SSSD identity binding before session startup.
- PAM account/session lifecycle enforcement.
- Authentication Result `S_OK` only after full authorization.
- Tests covering success, failure, replay, PAM failure, and classic login preservation.

## Required live authorization chain

A live RDSAAD/BAF session may start only after:

1. RDSAAD was negotiated.
2. Runtime broker-auth RDSAAD config is enabled and complete.
3. Server nonce was sent.
4. Authentication Request PDU was parsed.
5. `rdp_assertion` was extracted and size-checked.
6. Assertion was validated by the BAF JWT provider.
7. Replay was reserved through the trusted replay service.
8. Linux identity was resolved through NSS/SSSD-compatible lookup.
9. UID 0 was rejected by default.
10. PAM account approval succeeded.
11. Required PAM credential/session lifecycle can run.
12. Session startup uses the resolved Linux username.

## Acceptance criteria

- RDSAAD assertion authorization bridges from libxrdp to xrdp/sesman/sesexec safely.
- sesman/sesexec dispatch BAF login requests.
- `login_info` or equivalent supports BAF-authenticated sessions without raw assertions or passwords.
- `S_OK` is emitted only after full authorization.
- Classic SYS/UDS login behavior remains unchanged.
- No username/password assertion overloading exists.
- No custom IGEL client, FreeRDP plugin, DVC, or endpoint helper is required.
- No raw assertion logging exists.
- All BAF-specific tests pass.
