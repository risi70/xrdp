# Broker Authentication Assertion Specification

**BAF Assertion Profile:** 1.0
**Media type:** `application/baf+jwt`

## 1. Requirements

| ID | Requirement |
|---|---|
| AST-001 | Assertions MUST be JWS Compact Serialization JWTs. |
| AST-002 | Assertions MUST use an asymmetric algorithm from the configured allow-list. |
| AST-003 | Validators MUST reject `none`, all MAC algorithms, duplicate JSON members, unknown critical headers, and algorithm/key-type confusion. |
| AST-004 | Every mandatory claim MUST be validated independently of signature validity. |
| AST-005 | `(iss,jti)` MUST be accepted at most once within the replay window. |
| AST-006 | `target` MUST match the local target identity using exact, case-sensitive comparison. |
| AST-007 | Validators MUST NOT follow token-provided `jku`, `x5u`, or embedded `jwk` values. |
| AST-008 | Assertion lifetime MUST NOT exceed configured `max_lifetime`, default 300 seconds. |

## 2. JOSE header

Mandatory protected headers are:

| Header | Rule |
|---|---|
| `alg` | `RS256` for 1.0 interoperability; `PS256` or `ES256` MAY be enabled explicitly. |
| `kid` | Non-empty identifier unique within the issuer trust set. |
| `typ` | Exact value `baf+jwt`. |

`RS256` is mandatory because mature JOSE/OpenSSL implementations support it
widely. New deployments SHOULD prefer `PS256` when all participants support
it. RSA keys MUST be at least 2048 bits. ES256 keys MUST use P-256. SHA-1,
HMAC, unsecured JWTs, and keys selected from assertion-controlled URLs are
prohibited.

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

## 5. Validation order

Validators MUST:

1. Enforce configured maximum encoded size before allocation (default 16 KiB).
2. Parse exactly three compact-JWS segments with strict base64url.
3. Reject duplicate header or claim members.
4. Enforce `typ`, algorithm allow-list, `kid`, issuer-bound trust anchor, and
   key strength before signature verification.
5. Verify signature over received octets; never reserialize before verifying.
6. Validate schema and exact issuer.
7. Validate audience membership.
8. Require `iat <= nbf < exp`, `exp-iat <= max_lifetime`, and
   `iat <= now+clock_skew`.
9. Accept when `now+clock_skew >= nbf` and `now-clock_skew < exp`.
10. Match target and configured assurance/device/role policy.
11. Resolve and canonicalize NSS identity.
12. Atomically reserve `(iss,jti)` before reporting success.

Default `clock_skew` is 30 seconds and MUST NOT exceed 120 seconds. Clock
synchronization through systemd-timesyncd, chrony, or equivalent is required.

## 6. Replay protection

The cache key is `SHA-256(UTF8(iss) || 0x00 || UTF8(jti))`; raw assertions are
never stored. Atomic insert-if-absent is required. Entries expire at
`exp + clock_skew`. Cache capacity and rate limits are bounded.

States are `reserved`, `consumed`, and `released`. Validation reserves the key.
Successful PAM account acceptance consumes it. Failures caused by internal
transient errors MAY release a reservation; signature, policy, NSS, and PAM
denials MUST consume it to prevent probing. Cache unavailability fails closed.
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
mandatory claims require a new profile version and media type. Algorithm
support is configuration-gated, never inferred from the token.
