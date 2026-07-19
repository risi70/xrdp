# Broker-RDP Handle Ingress

Broker-RDP Handle (SD-009 Track 1) lets stock, unmodified RDP clients start a
broker-authorized session without RDSAAD support and without carrying the
assertion. The broker registers the full BAF assertion server-side with the
trusted handle service (`xrdp-baf-handled`); registration-side validation and
SD-006/SD-007 handle semantics are unchanged (256-bit single-use handles,
30–120 s TTL, target-bound, atomic consume). The client carries only the
64-character lowercase-hex handle.

Two delivery channels feed the same authorization chain
(`baf_authorize_assertion`: trusted replay service → JWT validation →
NSS/SSSD identity binding → UID 0 rejection → PAM account preconditions →
group access policy):

## Naming: "Mode C" in the code and config

"Broker-RDP Handle" is the descriptive name for this ingress. In the **source
and configuration it is still called "Mode C"** — its internal codename from
[SD-009](../specification/decisions/SD-009-robust-ingress-tracks.md), where it
was the third robust-ingress *track* after **Mode A** (native RDSAAD client) and
**Mode B** (broker-gateway RDSAAD), both now superseded and archived under
[`archive/`](archive/). When reading the tree you will see the old codename in:

| Where | Identifier |
|---|---|
| C / Python symbols | `modec_*` — e.g. `modec_resolve_handle`, `modec_preauth`, `modec_sec` |
| `sesman.ini` `[BrokerAuth]` | `ModeCOneTimeCredential` |
| `xrdp.ini` `[Globals]` | `broker_auth_modec_ingress_enabled` |
| tests / lab | `test_modec_live.c`, `test-lab/phase6/modec-smoke/` |

They all denote the Broker-RDP Handle mechanism described here. The codename was
deliberately left in the identifiers and config keys so existing build and
config files keep working; only the human-readable prose was renamed.

## Channel 1 - Routing token (pre-MCS, no credential fields)

The client sends the handle as an X.224 routing token of the exact form:

```text
Cookie: msts=<64 lowercase hex>
```

For example via FreeRDP `/load-balance-info:"Cookie: msts=<handle>"` or the
`loadbalanceinfo` `.rdp` property. Flow:

1. `xrdp_iso_incoming()` strictly parses the token; anything not matching the
   exact form is ignored as a normal cookie. Capture only happens when
   `broker_auth_enabled` and `broker_auth_modec_ingress_enabled` are set in
   xrdp.ini `[Globals]`.
2. After TLS is established and before MCS, `xrdp_sec_modec_preauth()`
   dispatches the handle through the owner callback and SCP/EICP
   (`credential_kind = HANDLE`) to sesman/xrdp-sesexec.
3. xrdp-sesexec gates on `baf_runtime_config_validate_mode_c()`, consumes the
   handle in the handle service, recovers the assertion, and runs the full
   authorization chain. Success creates session-ready login state exactly
   like RDSAAD preauth; any failure drops the connection before MCS.

## Channel 2 - One-time credential (password field)

The client logs in normally with the broker-designated username and the
handle as the password. In `authenticate_and_authorize_connection()`:

1. A handle-shaped password (exactly 64 lowercase hex chars) with Broker-RDP Handle
   enabled is routed to `mode_c_authenticate()` exclusively — it never
   reaches the PAM password stack and never falls back to password
   authentication.
2. The handle is consumed, the assertion recovered and authorized, and the
   NSS-resolved username (or the assertion `preferred_username`) must match
   the supplied username.
3. Failures observe the constant-time login-failure floor and emit AUTHFAIL
   log lines for fail2ban.

The handle is a reference, not the assertion: raw assertions never travel in
routing, username, or password fields (AST-015 as amended by SD-009).

## Configuration

sesman.ini `[BrokerAuth]` (all fail closed):

```ini
BrokerAuthEnabled=true
ModeCOneTimeCredential=true   ; enables both Broker-RDP Handle channels in sesexec
AllowSessionStart=true        ; required, as for RDSAAD live activation
HandleSocket=                 ; empty selects the built-in default path
; Issuer/KeyId/TrustAnchor/ExpectedAudience/LocalTarget/ReplaySocket
; are required exactly as for RDSAAD.
```

xrdp.ini `[Globals]`, for the routing-token channel only:

```ini
broker_auth_enabled=true
broker_auth_modec_ingress_enabled=true
```

Broker-RDP Handle does not require `RDSAADEnabled`. `RequireNonceBinding` does not apply
to Broker-RDP Handle (no challenge exchange); Broker-RDP Handle freshness comes from
registration-time replay reservation plus the handle TTL.

## Failure behavior

Unknown, expired, consumed, malformed, or target-mismatched handles, handle
service unavailability, replay service unavailability, identity/PAM denial,
and disabled or incomplete configuration all fail closed. Handle resolution
consumes the handle even when later stages fail (SD-007).
