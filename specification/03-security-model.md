# BAF Security Model

## 1. Security objectives and assets

| ID | Objective |
|---|---|
| SEC-001 | Only a configured issuer possessing an approved private key can authenticate a broker session. |
| SEC-002 | An assertion is usable once, on one intended target, for a short bounded interval. |
| SEC-003 | Remote identity cannot bypass NSS mapping, sesman authorization, or PAM account/session policy. |
| SEC-004 | Secrets, assertions, private keys, and sensitive device identifiers do not enter logs. |
| SEC-005 | Failure of broker infrastructure fails closed for broker login without damaging classic PAM availability. |
| SEC-006 | Security-relevant decisions produce correlated, tamper-resistant audit records. |

Assets are signing keys, trust configuration, assertions, replay state, Linux
UIDs and group membership, PAM policy, broker/Keycloak sessions, XRDP session
handles, audit records, and desktop data.

Actors are users, administrators, broker operators, IdP/LDAP operators, VDI
hosts, attackers controlling a client/network/account, and compromised
services.

## 2. STRIDE analysis

| Threat | Example | Controls | Residual risk |
|---|---|---|---|
| Spoofing | Fake broker or user | JWS signature, exact `iss/aud/target`, NSS mapping, PAM account | Issuer private-key compromise |
| Tampering | Alter target/username | JWS integrity; strict parser | JOSE library vulnerability |
| Repudiation | User denies login | Correlated issuer, hashed JTI, session ID, UID audit | Shared broker accounts |
| Information disclosure | Token in log/core dump | Secret handling, redaction, dump restrictions, short TTL | Compromised XRDP process memory |
| Denial of service | Huge tokens, JWKS storms, replay-cache flood | Size/rate/time bounds, negative key cache, bounded replay DB | Resource exhaustion at allowed limits |
| Elevation of privilege | Assert `root`, skip PAM | NSS policy, prohibited-user rules, local validation capability, PAM account/session | Misconfigured NSS/PAM |

## 3. Boundary-specific threats

### 3.1 Client and token theft

RDP TLS is mandatory. Assertions MUST NOT appear in command lines, URLs,
environment variables, process titles, or logs. Memory buffers are erased
after use where practical. A stolen assertion remains constrained by expiry,
target, audience, and JTI replay. Optional channel binding is reserved for a
future profile because standard RDP clients do not expose a stable exporter.

### 3.2 Broker or issuer compromise

A compromised issuer can impersonate identities within its configured policy.
Mitigations are per-issuer target/audience constraints, prohibited local users,
maximum assurance policy, short lifetime, key revocation, issuer disablement,
and independent PAM account policy. Broker roles MUST NOT map directly to UID
0 or sudo authorization.

### 3.3 XRDP compromise

Compromise of unprivileged `xrdp` can steal assertions in transit but cannot
manufacture a validated capability. `sesexec` validates the original token.
Local transports use filesystem permissions and peer credentials. Privilege
separation, systemd hardening, and least privilege remain mandatory.

### 3.4 LDAP/SSSD compromise

Compromised identity mapping can redirect names to privileged UIDs. Reverse UID
lookup, prohibited UID/name policy, SSSD TLS/SASL, directory ACLs, cache
protection, and PAM policy reduce risk. BAF never trusts assertion groups as
Linux groups.

### 3.5 Keycloak compromise

Keycloak compromise affects a broker only if the broker relies on it and then
issues a BAF assertion. XRDP trusts the configured BAF issuer, not arbitrary
Keycloak access tokens. Broker-side OIDC must validate issuer, client,
redirect URI, nonce, state, PKCE, and authentication context.

## 4. Privilege and policy controls

- Default-deny `root`, UID 0, system accounts, empty shell, and configurable
  UID ranges for broker login.
- Assertion roles/groups are policy inputs, never authoritative Linux groups.
- NSS forward lookup followed by UID reverse lookup is mandatory.
- PAM account rejection is final even after valid broker authentication.
- PAM session failures terminate startup and consume the replay identifier.
- Provider plugins are compile-time or root-configured trusted code, not
  dynamically selected by the client.

## 5. Cryptographic and secret management

Private issuer keys reside outside XRDP, preferably in HSM/KMS or Keycloak/
broker credential storage. VDI hosts hold only public anchors. Local trust files
are root-owned mode 0644 or stricter; configuration is root-owned and not
writable by the XRDP service account. Remote JWKS uses HTTPS with normal PKIX
validation and optional CA/SPKI pinning.

Algorithms follow RFC 8725 explicit allow-listing. Keys rotate with overlap;
old keys remain until all assertions expire, then are removed. Clock services
are monitored.

## 6. Logging and audit

| Event | Required fields |
|---|---|
| Validation success/failure | timestamp, host, issuer, `kid`, hashed JTI, target, outcome/reason class, client IP policy permitting |
| Identity mapping | issuer, subject hash, asserted name, canonical name, UID, outcome |
| PAM decision | canonical user, PAM service, account/session phase, outcome |
| Session lifecycle | broker session ID hash, XRDP session/display ID, start/end, termination reason |
| Key/replay events | issuer, `kid`, refresh result, cache health, replay detection |

Raw token, signature, access token, passwords, full device evidence, and private
keys MUST NOT be logged. Client errors use coarse codes; audit logs retain
specific codes. Journald access is restricted and forwarded to append-only SIEM
storage. Correlation identifiers are random and not authentication secrets.

## 7. Availability and limits

Default limits: 16 KiB assertion, 256 groups, 256 roles, 5-minute lifetime,
30-second skew, one unknown-key refresh per issuer per 30 seconds, bounded JWKS
and replay caches, and per-source authentication rate limiting. Parser and
signature work occur after cheap framing/size checks.

## 8. Recovery procedures

1. **Key exposure:** disable issuer/key, publish replacement, flush caches,
   search audit by `kid`, and evaluate active-session termination.
2. **Broker compromise:** disable issuer, preserve classic PAM, revoke broker
   sessions, rotate keys and client credentials.
3. **VDI compromise:** isolate host, revoke host credentials, rotate local
   trust/configuration, invalidate replay store, rebuild from image.
4. **LDAP/SSSD compromise:** block broker login, restore directory integrity,
   invalidate SSSD caches, review UID mappings and sessions.
5. **Replay-store corruption:** fail closed, replace store, retain forensic
   copy, and alert; never silently fall back to no replay protection.
6. **Clock incident:** stop broker acceptance when skew exceeds policy.

## 9. Security acceptance gates

No release is acceptable until malformed JOSE fuzzing, algorithm-confusion,
unknown-key SSRF, replay races, target mismatch, privileged-user mapping,
PAM-account denial, token redaction, and cache-failure tests pass. Threat-model
changes require security review and an update to the traceability matrix.
