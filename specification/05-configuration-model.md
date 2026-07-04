# Configuration Model

## 1. Principles

Configuration is local, root-controlled, fail-closed, reloadable only where
safe, and independent of assertion contents. Client input cannot select an
issuer, key URL, algorithm, target alias, or provider.

| ID | Requirement |
|---|---|
| CFG-001 | Broker authentication defaults to disabled. |
| CFG-002 | Unknown keys, duplicate keys, invalid types, and insecure permissions MUST fail configuration validation. |
| CFG-003 | Issuer policy MUST bind issuer, keys, algorithms, audiences, targets, and assurance requirements. |
| CFG-004 | Runtime assertion headers MUST NOT override trust configuration. |
| CFG-005 | Secret values SHOULD use systemd credentials or root-readable files, not inline configuration. |

## 2. Files

### 2.1 `sesman.ini`

A new `[BrokerAuth]` section owns global validator policy. Repeated
`[BrokerIssuer:<name>]` sections own issuer policy. Existing security and
session sections remain authoritative.

```ini
[BrokerAuth]
Enable=false
Mode=classic
Provider=jwt
Audience=urn:baf:xrdp:production
Target=urn:baf:desktop:tenant:pool:host
MaxAssertionBytes=16384
MaxLifetimeSeconds=300
ClockSkewSeconds=30
ReplayBackend=memory
ReplayCapacity=100000
JwksConnectTimeoutMs=2000
JwksTotalTimeoutMs=5000
AllowStaleJwksSeconds=0
DeniedUsers=root
MinimumUid=1000

[BrokerIssuer:example]
Issuer=https://broker.example.test
JwksUri=https://broker.example.test/.well-known/jwks.json
TrustFile=
AllowedAlgorithms=RS256
RequiredAssurance=urn:example:aal2
RequiredRoles=desktop-user
DeviceTrust=trusted,unknown
Enabled=true
```

### 2.2 `xrdp.ini`

Each relevant connection profile declares `auth_mode=classic|broker|auto` and
`broker_assertion=ask` or an internal autologin source. The assertion is
handled as secret input. `auto` means explicit protocol capability selection,
not guessing whether a password resembles a JWT.

### 2.3 Trust and replay files

- Trust files: `/etc/xrdp/broker-trust.d/<issuer>.{pem,jwks}`, root-owned.
- JWKS cache: `/var/cache/xrdp/broker-jwks/`, service-owned, atomic writes.
- Replay state: `/run/xrdp/broker-replay/` for non-persistent local cache or
  `/var/lib/xrdp/broker-replay/` when restart persistence is required.

## 3. Configuration schema

| Key | Type/default | Validation |
|---|---|---|
| `Enable` | bool/false | Build support required when true. |
| `Mode` | enum/classic | `broker` requires at least one issuer. |
| `Provider` | string/jwt | Must name compiled provider. |
| `Audience` | string/no default | Required and non-empty in broker mode. |
| `Target` | string/no default | Required; stable exact identifier. |
| `MaxAssertionBytes` | int/16384 | 1024–65536. |
| `MaxLifetimeSeconds` | int/300 | 30–900. |
| `ClockSkewSeconds` | int/30 | 0–120. |
| `ReplayBackend` | enum/memory | `memory`, `sqlite`, or future registered adapter. |
| `ReplayCapacity` | int/100000 | 1000–10,000,000. |
| timeout values | int | 100–30000 ms. |
| `AllowStaleJwksSeconds` | int/0 | 0 disables stale use; maximum 86400. |
| `DeniedUsers` | string list/root | Always implicitly includes UID 0. |
| `MinimumUid` | int/1000 | 0–2^31-1; UID 0 still denied. |

Issuer names are local labels only. `Issuer` values must be unique exact URIs.
Exactly one of `JwksUri` or `TrustFile` is required unless both refer to the
same administratively managed trust set for rotation. HTTPS is mandatory for
remote keys. Allowed algorithms cannot contain `none` or `HS*`.

## 4. Policy evaluation

Global policy and issuer policy combine by intersection:

```text
enabled
AND exact issuer
AND audience contains configured audience
AND target equals configured target
AND algorithm allowed globally and by issuer
AND assurance meets issuer policy
AND required roles are present
AND device status is allowed
AND NSS/PAM/local access policy permits user
```

Assertion groups/roles cannot loosen local policy. Missing optional policy
configuration means no additional broker role restriction, not permit-all
identity mapping.

## 5. Loading and reload

Startup validates the complete configuration and filesystem permissions before
opening the listener. `SIGHUP` parses into an immutable candidate, validates
all issuer trust, and atomically swaps policy only on complete success.
Existing validation operations retain their old immutable snapshot. Removing
an issuer or key affects new logins immediately; active sessions are unchanged
unless an explicit administrative termination policy exists.

Replay backend type/path and privilege settings require restart. JWKS content
and issuer enablement may reload. Configuration errors name file, section, and
key but never secret contents.

## 6. Future extensions

New provider and replay backend names use a registry documented with the
release. Unknown configuration is rejected in 1.x to catch mistakes. A future
`CompatibilityVersion` may permit controlled schema evolution. Broker-specific
configuration belongs in the broker, not XRDP.
