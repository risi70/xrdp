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

The trusted `[BrokerAuth]` section is default-disabled. When broker auth and
RDSAAD are both enabled for future preauth use, validation requires:

- `Provider=jwt`
- `TrustAnchor`
- `ExpectedAudience`
- `LocalTarget`
- `MaxAssertionSize`
- `ReplayBackend=service`
- `ReplaySocket`
- `RejectUid0=true`
- `AllowSessionStart=false`

Missing or unsafe values fail closed. Process-local replay is not accepted for
live/preauth authorization because replay protection must be service-backed.

## Session Start Gate

`AllowSessionStart` defaults to false and validation rejects true for this phase.
This preserves the current fail-closed RDSAAD behavior while giving sesexec a
trusted configuration object for the next bridge step.

The pre-MCS RDSAAD bridge is still incomplete. `S_OK` must not be emitted until
the future libxrdp-to-xrdp preauth owner, SCP/EICP dispatch, BAF validation,
trusted replay, NSS/SSSD identity binding, UID 0 rejection, and PAM
preconditions are all proven for the current connection.
