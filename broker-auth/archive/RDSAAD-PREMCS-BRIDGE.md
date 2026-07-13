# RDSAAD Pre-MCS Bridge

RDSAAD Authentication Request processing runs inside `libxrdp` before MCS and
before `xrdp_wm` / `xrdp_mm` exist. Direct use of `xrdp_mm` at this point is
unsafe because the module/session state and client MCS parameters needed for
session creation have not been negotiated yet.

The selected bridge uses the existing `xrdp_session` owner callback. `libxrdp`
parses a bounded `rdp_assertion`, calls the trusted xrdp owner, clears the raw
assertion, and sends Authentication Result. `libxrdp` does not call sesman,
sesexec, NSS, PAM, or session startup directly.

The xrdp owner connects to sesman over SCP and sends the dedicated broker login
request. Sesman validates that trusted live BrokerAuth config is enabled, starts
sesexec, and forwards the bounded assertion over EICP. Sesexec loads only
trusted sesman configuration from `[BrokerAuth]`, creates the JWT validator with
service-backed replay, binds the identity through NSS, rejects UID 0 by default,
and runs the broker PAM account/session preconditions. Client-provided
`xrdp_client_info` values are metadata only and are not trusted validation
configuration.

On success, sesexec creates session-ready `login_info` for the resolved Linux
user. Sesman marks the SCP connection as `E_SLI_LOGIN_BAF`. The xrdp owner keeps
that authenticated SCP transport bound to the current `xrdp_process`; no raw
assertion, token UID/GID, token groups, or password placeholder is stored. After
MCS creates `xrdp_wm` and `xrdp_mm`, `xrdp_mm` adopts the authenticated sesman
transport and continues with the normal create-session path.

`S_OK` may be emitted only after the callback receives a successful sesman /
sesexec authorization result. Any parser, replay, identity, PAM, config, or
service failure maps to an Authentication Result failure and the RDP connection
does not continue to MCS.

Live activation remains gated by trusted sesman config. `AllowSessionStart` defaults to `false`; enabling live RDSAAD activation requires the administrator
to configure the complete trusted JWT, replay-service, target, and session-start
settings locally on the server.
