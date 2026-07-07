# BAF Deployment Notes

This document describes the Phase 5 reference deployment shape. It is not a
production-readiness claim.

## Build Options

Build XRDP with broker authentication enabled:

```sh
./bootstrap
./configure --disable-rfxcodec --enable-broker-auth
make
```

Broker-auth remains compile-time gated and runtime disabled by default.

## Required Services

- `xrdp`
- `xrdp-sesman`
- `xrdp-sesexec`
- trusted BAF replay service, for example `xrdp-baf-replayd`
- NSS/SSSD or equivalent NSS-compatible account resolution
- PAM service policy for XRDP session startup
- external broker or the Phase 5 reference broker simulator

## Trusted Runtime Configuration

BAF live activation uses trusted local sesman/sesexec configuration, not
RDP-client supplied values. The local `[BrokerAuth]` configuration must provide:

- broker-auth enabled flag;
- RDSAAD enabled flag;
- provider `jwt`;
- issuer;
- key ID;
- RS256 allowed algorithm;
- trust anchor path;
- expected audience;
- local target;
- maximum assertion size;
- replay backend `service`;
- replay service socket;
- UID 0 rejection;
- explicit session-start allowance.

`AllowSessionStart` is disabled by default. Enabling it is an administrator
decision after the trust anchor, replay service, NSS/SSSD, and PAM paths are in
place.

## Trust Anchor and Broker Key Setup

The broker signs BAF assertions with an RS256 private key. XRDP sesexec trusts
only the configured public key/trust anchor. Test keys under this repository are
for automated tests only and must not be used in deployments.

Rotate broker keys by deploying a new trusted public key and matching configured
key ID before issuing assertions with the new private key. JWKS rotation is
deferred from the minimal Phase 5 simulator.

## NSS/SSSD Requirements

The assertion's `preferred_username` is not sufficient by itself. The resolved
Linux account must come from NSS/SSSD-compatible lookup, and UID 0 is rejected
by default. Token UID/GID/home/shell/group claims are not trusted.

## PAM Requirements

Classic password login still calls `pam_authenticate()`. Broker-auth skips
`pam_authenticate()` but must pass PAM account checks and required
credential/session lifecycle before live session startup.

## IGEL and RDP Client Assumptions

The endpoint uses the standard RDP/RDSAAD-compatible flow. The BAF MVP does not
require a custom IGEL client, IGEL helper, FreeRDP plugin, dynamic virtual
channel, or endpoint helper. Smartcard redirection remains separate from broker
SSO.

## Test Procedure

1. Build with `--enable-broker-auth`.
2. Start the trusted replay service.
3. Configure `[BrokerAuth]` with the broker trust anchor, audience, target,
   replay socket, and explicit session-start allowance.
4. Confirm NSS resolves the expected Linux user and PAM account/session policy
   permits that user.
5. Use the reference broker to issue a target-bound assertion.
6. Submit the assertion through the RDSAAD Authentication Request path.
7. Verify `S_OK` is emitted only after full BAF authorization and the Ubuntu
   session starts as the resolved Linux user.

Automated repository tests cover the deterministic boundary. Full external
wire-level client automation remains release-lab work.

## Troubleshooting

- Authentication Result failure before MCS usually means parse failure,
  disabled config, invalid assertion, replay failure, identity failure, or PAM
  denial.
- Replay service unavailable must fail closed.
- Wrong audience or wrong target must fail validation.
- Unknown users, unsafe usernames, and UID 0 must fail authorization.
- Do not copy client-side or broker-supplied config values into trusted
  sesman/sesexec runtime config.

## Rollback

Disable broker-auth runtime config or rebuild without `--enable-broker-auth`.
Classic PAM/password login remains separate and unchanged.
