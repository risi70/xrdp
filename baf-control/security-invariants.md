# BAF Security Invariants

These invariants apply to all BAF implementation work.

## Assertion handling

- Raw assertions and raw tokens must not be logged.
- Raw assertion buffers must be bounded, validated, and cleared after handoff.
- Validator success alone is not login authorization.
- Transport success alone is not login authorization.
- Identity binding alone is not login authorization.
- Authentication Result `S_OK` must not be emitted before full authorization.

## Protocol ingress

- Selection between SD-008 RDSAAD-style ingress and the proposed SD-009 tracks is unresolved.
- RDSAAD is only an optional MS-RDPBCGR-compatible pre-logon assertion envelope.
- RDSAAD support must not imply Microsoft identity integration or compatibility with stock Entra clients carrying BAF assertions.
- Broker-RDP Handle remains an included ingress candidate under SD-006, SD-007, and proposed SD-009.
- The endpoint must remain a standard RDP client.
- Do not require a custom IGEL client, endpoint helper, FreeRDP plugin, or dynamic virtual channel.
- Do not use username or password fields to carry assertions.
- Keycloak is the primary user-facing IdP, but the broker must validate Keycloak/OIDC and issue a distinct broker-neutral BAF assertion.
- XRDP core must not validate Keycloak tokens or contain UDS-specific, Keycloak-specific, or Microsoft identity logic.

## Replay

- Live broker-auth activation requires the trusted replay service.
- Process-local memory replay is allowed only for unit tests and single-process test harnesses.
- Replay reservation must be single-use and fail closed on service unavailability.
- Replay service must not receive raw assertions.

## Identity

- Linux identity must be resolved through system NSS and authorized through PAM.
- Token UID/GID/home/shell/groups must not be trusted.
- UID 0 must be rejected by default.
- Unknown, unsafe, ambiguous, or unauthorized identities must fail closed.
- LDAP provisioning or synchronization, SSSD configuration or availability, Active Directory, Kerberos, domain join, and Microsoft Entra are out of scope and are not authentication prerequisites.

## PAM

- Classic login must continue to call `pam_authenticate()`.
- Broker-auth must not call `pam_authenticate()`.
- Broker-auth must run PAM account checks and required credential/session lifecycle before session startup.
- PAM account/session failure must fail closed.

## Session startup

- Live session startup must use the resolved Linux username.
- No session may start from a raw token, handle, assertion, or claim-only identity.
- Classic SYS/UDS login behavior must remain unchanged.
