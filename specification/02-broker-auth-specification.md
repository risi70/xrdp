# Broker Authentication Assertion Specification

**BAF Assertion Profile:** 1.0
**Media type:** `application/baf+jwt`

## 1. Requirements

| ID | Requirement |
|---|---|
| AST-001 | Assertions MUST be JWS Compact Serialization JWTs. |
| AST-002 | Phase 2 assertions MUST use RS256; all other algorithms MUST fail closed. |
| AST-003 | Validators MUST reject `none`, all MAC algorithms, duplicate JSON members, unknown critical headers, and algorithm/key-type confusion. |
| AST-004 | Every mandatory claim MUST be validated independently of signature validity. |
| AST-005 | `(iss,jti)` MUST be accepted at most once within the replay window. |
| AST-006 | `target` MUST match the local target identity using exact, case-sensitive comparison. |
| AST-007 | Validators MUST NOT follow token-provided `jku`, `x5u`, or embedded `jwk` values. |
| AST-008 | Assertion lifetime MUST NOT exceed configured `max_lifetime`, default 300 seconds. |
| AST-009 | The validator MUST NOT perform NSS, SSSD, PAM, LDAP, FreeIPA, Active Directory, local passwd, local group, or equivalent identity lookup. |
| AST-010 | A validated broker capability MUST NOT be treated as session authorization. |
| AST-011 | Linux identity binding through NSS/SSSD MUST succeed before PAM account/session processing or session creation. |
| AST-012 | Once reserved, an assertion MUST remain unusable until replay expiry, including after later-stage failure or a `released` state marker. |

## 2. JOSE header

Mandatory protected headers are:

| Header | Rule |
|---|---|
| `alg` | Exact value `RS256` for the Phase 2 MVP. |
| `kid` | Non-empty identifier unique within the issuer trust set. |
| `typ` | Exact value `baf+jwt`. |

Phase 2 is intentionally RS256-only. Its configured algorithm value MUST be
exactly `RS256`; `PS256`, `ES256`, `none`, all MAC algorithms, and mixed
allow-lists fail closed. RSA keys MUST be at least 2048 bits. PS256 and ES256
are future extensions requiring complete implementation, configuration, and
conformance tests before they can be enabled. SHA-1, HMAC, unsecured JWTs, and
keys selected from assertion-controlled URLs are prohibited.

BAF 1.0 defines an algorithm-agile extension model, but the Phase 2 MVP
implementation supports RS256 only. Advertising another algorithm in
configuration does not enable it.

## 3. Claims

| Claim | Type | M/O | Meaning |
|---|---|---:|---|
| `iss` | URI string | M | Configured broker assertion issuer. |
| `aud` | string or unique string array | M | Must include configured XRDP audience. |
| `sub` | string | M | Stable issuer-local user identifier; never used directly as Linux name. |
| `preferred_username` | string | M | Candidate NSS login name. |
| `groups` | unique string array | M | Informational broker groups; default empty. |
| `roles` | unique string array | M | Broker authorization roles; default empty. |
| `auth_method` | unique string array | M | Methods such as `pwd`, `otp`, `webauthn`. |
| `assurance_level` | string | M | Issuer-defined assurance URI/value evaluated by policy. |
| `broker_session_id` | string | M | Broker-side session correlation identifier. |
| `target` | string | M | Exact configured desktop target identifier. |
| `iat` | NumericDate integer | M | Issuance time. |
| `nbf` | NumericDate integer | M | Earliest acceptance time. |
| `exp` | NumericDate integer | M | Exclusive expiry time. |
| `jti` | string | M | Cryptographically unpredictable replay identifier. |
| `device_trust` | object | M | Device trust result; may be `{ "status":"unknown" }`. |
| `extensions` | object | O | Namespaced non-critical extensions. |

`device_trust.status` is one of `trusted`, `untrusted`, or `unknown`.
Optional `device_trust` members are `device_id`, `provider`, `evaluated_at`,
and namespaced `evidence`. Device identifiers are sensitive and SHOULD be
pseudonymous.

## 4. Normative JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://xrdp.example/spec/baf-assertion-1.0.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["iss","aud","sub","preferred_username","groups","roles",
    "auth_method","assurance_level","broker_session_id","target",
    "iat","nbf","exp","jti","device_trust"],
  "properties": {
    "iss": {"type":"string","format":"uri","minLength":1},
    "aud": {"oneOf":[
      {"type":"string","minLength":1},
      {"type":"array","minItems":1,"uniqueItems":true,
       "items":{"type":"string","minLength":1}}]},
    "sub": {"type":"string","minLength":1,"maxLength":255},
    "preferred_username": {
      "type":"string","minLength":1,"maxLength":255,
      "pattern":"^[^\\u0000-\\u001f\\u007f]+$"
    },
    "groups": {"type":"array","maxItems":256,"uniqueItems":true,
      "items":{"type":"string","minLength":1,"maxLength":255}},
    "roles": {"type":"array","maxItems":256,"uniqueItems":true,
      "items":{"type":"string","minLength":1,"maxLength":255}},
    "auth_method": {"type":"array","minItems":1,"maxItems":16,
      "uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":64}},
    "assurance_level": {"type":"string","minLength":1,"maxLength":255},
    "broker_session_id": {"type":"string","minLength":1,"maxLength":255},
    "target": {"type":"string","minLength":1,"maxLength":255},
    "iat": {"type":"integer","minimum":0},
    "nbf": {"type":"integer","minimum":0},
    "exp": {"type":"integer","minimum":0},
    "jti": {"type":"string","minLength":16,"maxLength":255},
    "device_trust": {
      "type":"object","additionalProperties":false,"required":["status"],
      "properties":{
        "status":{"enum":["trusted","untrusted","unknown"]},
        "device_id":{"type":"string","minLength":1,"maxLength":255},
        "provider":{"type":"string","minLength":1,"maxLength":255},
        "evaluated_at":{"type":"integer","minimum":0},
        "evidence":{"type":"object"}
      }
    },
    "extensions": {
      "type":"object","propertyNames":{"format":"uri"},
      "additionalProperties":true
    }
  }
}
```

## 4.1 Validation and transport size bounds

The configured validator maximum (16 KiB by default) is an upper bound on input
accepted by the validator API. It is not a transport guarantee. Each active
transport MUST enforce its own, potentially stricter bound before allocation or
forwarding.

For Phase 4b RDSAAD-style ingress, the effective assertion maximum is the
minimum of the configured validator maximum, the RDSAAD Authentication Request
JSON/parser bound, and any downstream internal transport bound if the assertion
is handed to SCP/EICP machinery. The MVP MUST NOT truncate assertions and MUST
reject oversize assertions before validation where possible.

The MVP does not fragment assertions, does not overload username/password
fields, and does not use generic out-of-band assertion handles. SD-008
RDSAAD-style pre-logon `rdp_assertion` is the selected production MVP ingress.
SD-006 one-time server-side handles are superseded for production ingress and
may remain only experimental/fallback/test code. Fragmentation, reassembly,
generic bearer handles, and larger internal messages require a future protocol
decision.

| ID | Requirement |
|---|---|
| AST-013 | A transport MUST enforce its effective assertion bound before forwarding to the validator. |
| AST-014 | The in-band effective maximum MUST be the minimum of validator, transport, and framed payload limits. |
| AST-015 | Oversize assertions MUST fail closed; MVP implementations MUST NOT fragment, overload username/password fields, or use generic out-of-band handles. SD-008 RDSAAD-style pre-logon `rdp_assertion` is the selected MVP ingress; SD-006 handles are superseded for production ingress. |

## 5. Validation order

Validators MUST:

1. Enforce configured maximum encoded size before allocation (default 16 KiB).
2. Parse exactly three compact-JWS segments.
3. Enforce strict base64url.
4. Reject duplicate JSON members in the protected header and claims.
5. Validate the protected header, including exact `typ = baf+jwt`, rejection
   of unknown critical headers, token-controlled key locations, embedded token
   keys, `alg = none`, and MAC algorithms.
6. Enforce the Phase 2 RS256-only algorithm allow-list.
7. Require a non-empty `kid`.
8. Select the issuer-bound trust anchor.
9. Enforce key strength.
10. Verify the JWS signature over the received octets; never reserialize
    before verifying.
11. Validate all mandatory claims and the assertion schema.
12. Validate the exact configured issuer.
13. Validate audience membership.
14. Require `iat <= nbf < exp`, `exp-iat <= max_lifetime`, and
    `iat <= now+clock_skew`; accept only when `now+clock_skew >= nbf` and
    `now-clock_skew < exp`.
15. Match the exact configured target.
16. Apply assurance, device, role, and other broker assertion policy prechecks
    that do not require local identity resolution.
17. Atomically reserve `(iss,jti)`.
18. Create and return a validated broker capability.

Default `clock_skew` is 30 seconds and MUST NOT exceed 120 seconds. Clock
synchronization through systemd-timesyncd, chrony, or equivalent is required.

The validator MUST NOT perform NSS, SSSD, PAM, LDAP, FreeIPA, Active
Directory, local `passwd`/`group`, or equivalent identity resolution. A
validated broker capability MUST NOT be treated as login authorization or
start a session. It proves only that the assertion is authentic, fresh,
targeted to this XRDP endpoint, compatible with assertion-level policy, and
non-replayed. Mandatory Linux identity binding is a later Phase 4a stage. Phase 4a
still produces no session authorization. Phase 4b may authorize session creation only
after a validated capability, separately resolved Linux identity, default UID 0
rejection, and required PAM preconditions are all present.

## 6. Replay protection

The cache key is `SHA-256(UTF8(iss) || 0x00 || UTF8(jti))`; raw assertions are
never stored. Atomic insert-if-absent is required. Entries expire at
`exp + clock_skew`. Cache capacity and rate limits are bounded.

States are `reserved`, `consumed`, and `released`. Validation reserves the key.
Phase 2 uses unconditional consume-once semantics: once reserved, the
assertion cannot be reserved again before expiry. Later identity-binding,
authorization, PAM account, or session-creation failure does not permit retry.
`released` is an audit/state marker only; it MUST NOT remove the entry or make
the assertion reusable. Transient-failure retry is not part of the MVP.
Cache unavailability fails closed.
For Phase 4b live activation, reservations MUST use the persistent host-local
trusted replay service defined by SD-004. Process-local memory is permitted
only in unit tests and isolated single-process harnesses. A worker MUST fail
closed on any unavailable or indeterminate service result and MUST NOT fall
back to its local memory backend.
Clustered desktops require a shared atomic replay store or target-specific
assertions that cannot move between hosts.

## 7. Target and broker identity

`target` is an administrator-configured stable identifier, not client-supplied
DNS. Recommended form is a URI such as `urn:baf:desktop:tenant:pool:host`.
Aliases are prohibited unless explicitly configured.

Broker identity is the tuple `(iss, trust-set, allowed-algorithms, audiences,
policy)`. Issuer strings are compared exactly after configuration-time URI
validation; runtime normalization is forbidden.

## 8. Trust anchors and rotation

Trust anchors are either local PEM/JWK files owned by root or JWKS fetched from
an administrator-configured HTTPS URL. Token `jku` is ignored. JWKS retrieval
uses TLS verification, size/time limits, an allow-list, cache-control bounded
by policy, and last-known-good keys. Rotation uses overlapping old/new keys
with distinct `kid`; unknown `kid` permits one rate-limited refresh.

Emergency revocation removes the key, flushes JWKS cache, blocks the issuer,
and optionally terminates sessions by `broker_session_id`.

## 9. Serialization and extensibility

The wire representation is the exact JWS Compact Serialization. Producers
SHOULD serialize header and payload using RFC 8785 JCS for reproducible vectors;
validators MUST verify received octets and MUST NOT require a particular JSON
member order. UTF-8, integers for NumericDate, and unique members are required.

New optional data belongs under `extensions` using URI keys. Unknown extension
keys are ignored unless named by a future understood critical policy. New
mandatory claims require a new profile version and media type. Future
algorithm support is configuration-gated, never inferred from the token.
Phase 2 accepts only an exact RS256 configuration.

## SD-008 RDSAAD-style ingress

SD-008 selects RDS AAD Auth-style pre-logon assertion ingress as the preferred MVP path. The client Authentication Request PDU carries `rdp_assertion`, a compact JWT/JWS BAF assertion, which feeds the existing BAF validator and trusted replay path. SD-006/SD-007 handles are superseded for production MVP ingress and may remain only experimental/fallback/test code. Live session activation still requires the full validation, replay, identity, UID, and PAM chain.
