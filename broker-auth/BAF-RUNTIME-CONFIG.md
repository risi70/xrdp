# BAF Runtime Configuration

## Ownership

sesman and xrdp-sesexec own the trusted Broker Authentication Framework
runtime configuration. The configuration is loaded from the local `sesman.ini`
file through the existing sesman config reader, and xrdp-sesexec obtains it
through its normal trusted startup path.

`xrdp_client_info` is not a trusted configuration source for sesexec. It belongs
to the RDP-facing xrdp/libxrdp side and may carry negotiated or client-adjacent
state. sesexec must not use it for trust anchors, audiences, replay sockets,
local targets, or session-start policy.

## Required Fields

The trusted `[BrokerAuth]` section is default-disabled. When a BAF ingress is
enabled for live preauth use, validation requires:

- `Provider=jwt`
- `TrustAnchor`
- `ExpectedAudience`
- `LocalTarget`
- `MaxAssertionSize`
- `ReplayBackend=service`
- `ReplaySocket`
- `RejectUid0=true`
- `AllowSessionStart` (defaults to `false`; live activation requires explicit `true`)

Missing or unsafe values fail closed. Process-local replay is not accepted for
live/preauth authorization because replay protection must be service-backed.

## Session Start Gate

`AllowSessionStart` defaults to false. Live activation requires an explicit true
value in trusted local configuration and still succeeds only after every BAF,
replay, system NSS, UID, and PAM prerequisite passes.

`S_OK` must not be emitted until the libxrdp-to-xrdp preauth owner, SCP/EICP
dispatch, BAF validation, trusted replay, system NSS identity binding, UID 0
rejection, and PAM preconditions are all proven for the current connection.
