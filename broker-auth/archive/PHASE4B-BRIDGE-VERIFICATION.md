# Phase 4b Bridge Verification

## Verification Scope

Verified commit target: `5ecc96ec` (`baf: add pre-MCS RDSAAD authorization bridge`).

Verification was performed on branch `mvp-broker-assertion` at
`8fa1beb6236c2ceb7cda40965f71181075115c07`, which includes the target commit.
Local `HEAD` and `origin/mvp-broker-assertion` were aligned before this note was
added.

This verification is focused on the pre-MCS RDSAAD authorization bridge. It does
not add new bridge behavior.

## Files Inspected

- `libxrdp/libxrdpinc.h`
- `libxrdp/xrdp_sec.c`
- `xrdp/xrdp_wm.c`
- `xrdp/xrdp_process.c`
- `xrdp/xrdp_types.h`
- `xrdp/xrdp_mm.c`
- `libipm/scp.[ch]`
- `libipm/eicp.[ch]`
- `sesman/scp_process.c`
- `sesman/eicp_process.c`
- `sesman/sesexec/eicp_server.c`
- `sesman/sesexec/login_info.[ch]`
- `sesman/libsesman/baf_runtime_config.[ch]`
- `sesman/libsesman/baf_authorization.[ch]`
- `sesman/libsesman/baf_identity.[ch]`
- `sesman/libsesman/verify_user_pam.c`
- `tests/baf/test_premcs_bridge_contract.py`
- `tests/baf/test_security_contract.py`
- `tests/baf/test_pam_broker_contract.py`

## Findings

`libxrdp` parses the RDSAAD Authentication Request and extracts
`rdp_assertion` in `xrdp_sec_rdsaad_exchange()`. It does not call NSS, PAM,
sesman, sesexec, or session startup directly. Authorization is delegated through
`XRDP_CALLBACK_RDSAAD_PREAUTH` to the owning xrdp process layer.

The callback path is available before `xrdp_wm` and `xrdp_mm` exist. The xrdp
process layer sends the assertion over the dedicated broker SCP request path and
stores successful preauth state on the current `struct xrdp_process`. Later
`xrdp_mm_connect()` adopts only that session-bound authenticated sesman
transport, preventing reuse by another connection.

The existing broker IPC types are semantically used as the BAF preauth carrier:
`E_SCP_BROKER_LOGIN_REQUEST_V1` and `E_EICP_BROKER_LOGIN_REQUEST_V1`. They carry
bounded assertion bytes and connection metadata, not a password. The request
buffers are erased after use, and no production logging of raw assertions was
found.

sesman dispatches broker login requests in `sesman/scp_process.c` and forwards
them to sesexec over EICP. sesexec dispatches broker login requests in
`sesman/sesexec/eicp_server.c` and invokes
`login_info_baf_preauth_user()`.

sesexec uses trusted local BAF runtime config from `g_cfg->baf` and
`baf_runtime_config_validate_live()`. It does not use `xrdp_client_info` as a
trusted validator/replay/session-start configuration source. Live/preauth
authorization requires service-backed replay, trusted JWT validation,
identity-binding capability, NSS/SSSD-compatible local identity resolution,
UID 0 rejection by default, PAM account approval, and session credential/session
readiness through the existing broker PAM path.

`login_info` has a distinct BAF preauth creation path. It stores the resolved
Linux username/session metadata needed for session startup and does not store a
password, raw assertion, token UID/GID, or token-derived Unix groups.

Classic SYS and UDS login dispatch remains present and separate. Classic PAM
password login still uses the existing PAM authentication path; broker-auth
preauth does not call `pam_authenticate()`.

## S_OK Gating

`S_OK` is emitted only if the preauth callback returns
`XRDP_RDSAAD_PREAUTH_AUTHORIZED`. All other callback statuses, malformed request
parse failures, missing assertions, oversized assertions, invalid assertions,
replay failures, trusted-config failures, replay-service failures, identity
binding failures, UID 0 rejection, and PAM account/session failures map to a
failure Authentication Result.

`xrdp_sec_rdsaad_exchange()` returns failure when the Authentication Result is
not `S_OK`, so the connection does not proceed to MCS/session startup after a
failed RDSAAD preauth exchange.

## Tests Run

- `./bootstrap` passed. It emitted an existing non-fatal `ulalaca` pathspec
  warning.
- `./configure --disable-rfxcodec --enable-broker-auth` passed. Configure
  reported `libcheck` was not found, so broad C unit tests are limited.
- `make -j"$(nproc)"` passed.
- `make -C tests/baf check` passed: 12/12 tests.
- `python3 tests/baf/test_security_contract.py` passed.
- `python3 tests/baf/test_pam_broker_contract.py` passed.
- `make check` ran the BAF suite successfully and then failed in `tests/common`
  because `check.h` was unavailable. This is an environment dependency issue
  from missing `libcheck`, not a Phase 4b bridge regression.

## Security Boundary Searches

Focused searches found no production username/password assertion overloading, no
BAF dependency on custom IGEL client behavior, FreeRDP plugins, or dynamic
virtual channels, no production raw assertion logging, no production
Keycloak/Entra/UDS-specific BAF hard-coding, and no `trusted=true` bypass.
Matches were limited to documentation, security-contract tests, existing XRDP
DVC implementation code unrelated to BAF ingress, or existing classic token-login
debug text unrelated to raw BAF assertions.

## Remaining Issues

- Broad `make check` remains limited until `libcheck` is installed in the build
  environment.
- This verification did not exercise an external wire-level RDSAAD client. The
  deterministic bridge, IPC, authorization-contract, and security-contract tests
  cover the implemented boundary.
- Operational live success still requires a trusted local `[BrokerAuth]`
  configuration with session activation enabled and a reachable trusted replay
  service.

## Closure Recommendation

Close Phase 4b bridge. The pre-MCS owner callback, sesman/sesexec BAF preauth
dispatch, trusted runtime config usage, session-bound authorization state, and
`S_OK` gating are implemented and covered by BAF-specific tests. Phase 5
broker-specific integration and external interoperability remain separate.
