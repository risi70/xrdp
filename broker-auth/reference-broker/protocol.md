# Reference Broker Protocol

The Phase 5 reference broker protocol is a local, broker-neutral interface for
tests and adapter development. It is not an XRDP wire protocol and is not part
of SCP/EICP.

## Operations

### `list_targets(user)`

Returns the Ubuntu VDI targets available to a broker-authenticated user after
local policy checks. The result contains broker-neutral target names, RDP host
addresses, and the expected BAF audience.

### `assign_target(user, target)`

Creates a broker session ID for one user and one target. The assignment must
exist before assertion issuance.

### `create_session_assertion(user, target, broker_session_id, auth_context)`

Issues one BAF assertion for the assigned user and target. The assertion:

- uses RS256 for the current MVP;
- is short-lived;
- is bound to `aud` and `target`;
- contains `jti` for single-use replay reservation;
- contains only broker identity metadata, not Unix UID/GID/group authority;
- is never logged by the reference broker.

Required claims are:

- `iss`
- `aud`
- `sub`
- `preferred_username`
- `target`
- `broker_session_id`
- `auth_method`
- `assurance_level`
- `iat`
- `nbf`
- `exp`
- `jti`

The repository schema also requires `groups`, `roles`, and `device_trust`.
XRDP does not treat those claims as Unix group authority.

### `launch_connection(user, target)`

Assigns a target, creates a session assertion, and returns a launch descriptor
containing:

- `protocol = RDSAAD`;
- RDP server address;
- target name;
- broker session ID;
- RDSAAD Authentication Request body with `rdp_assertion`.

The launch descriptor is compatible with a standard RDP/RDSAAD-capable client
flow. It does not require username/password assertion overloading, a custom IGEL
client, a FreeRDP plugin, a dynamic virtual channel, or an endpoint helper.

### `revoke_session(broker_session_id)`

Revokes broker-side session state. Replay protection for a submitted assertion
remains XRDP's trusted replay service responsibility.

## Authorization Boundary

The reference broker may authenticate a user and select a target, but XRDP
sesexec remains responsible for live session authorization:

```text
RDSAAD rdp_assertion
-> BAF JWT validation
-> trusted replay service
-> NSS/SSSD identity binding
-> UID 0 rejection
-> PAM account/session preconditions
-> session-ready login_info
```

Validator success alone is not a session authorization result.

## Mode A and Mode B

Mode A native RDSAAD client mode and Mode B broker gateway RDSAAD mode use the
same broker-neutral assertion contract. In Mode A the endpoint client carries
`rdp_assertion` to XRDP. In Mode B a broker gateway receives the broker session
and assertion, then performs RDSAAD toward XRDP.

The reference broker stays UDS-neutral. UDS-specific mapping belongs only in the
`uds-adapter/` reference adapter.

This contract is not SCP/EICP.
No username/password assertion transport is allowed.
