# RDSAAD Pre-MCS Bridge

The pre-MCS RDSAAD bridge is still intentionally incomplete. The required owner
mechanism must connect the libxrdp RDSAAD exchange to trusted xrdp-side code,
then to sesman and xrdp-sesexec, without using `xrdp_mm` before it exists.

## Trusted Runtime Config

The trusted BAF runtime configuration foundation now lives in the sesman config
model. sesman and xrdp-sesexec load the local `[BrokerAuth]` section from
`sesman.ini`; they do not use `xrdp_client_info` as a trust source.

This gives future preauth dispatch code a local source for provider, trust
anchor, audience, local target, assertion size, service replay socket, UID 0
rejection, and the session-start gate. `AllowSessionStart` remains false and
validation rejects true in this phase, so the current RDSAAD hook still withholds
`S_OK`.
