# Phase 1 — Upstream-safe foundation

Phase 1 adds compile-time scaffolding only. It does not implement JWT/JWS
parsing, assertion transport, NSS mapping, PAM bypass, or broker login.

## Added

- `--enable-broker-auth`, disabled by default.
- A generic request carrying opaque bytes plus future configuration, audience,
  target, client-address, and test-clock inputs.
- Opaque provider result and prevalidated identity declarations.
- Structured provider statuses.
- A null provider that always returns `unsupported` and no result.
- Build and source-contract tests.

## Security boundary

There is no callable prevalidated PAM entry and no broker path into
`login_info` or session startup. `AUTH_PROVIDER_SUCCESS` is reserved, but Phase
1 cannot construct the opaque result or identity types. Classic authentication
remains upstream `auth_userpass()` and still calls `pam_authenticate`,
`pam_acct_mgmt`, and the existing PAM session lifecycle.

## Build and test

```sh
./configure
make
make check

./configure --enable-broker-auth
make
make check
```

The enabled test confirms the null provider fails closed. The authentication
contract test confirms classic PAM calls remain and no trusted bypass exists.

## Deferred

JWT/JWS validation and replay are Phase 2. SCP/EICP assertion transport is
Phase 3. NSS mapping and capability-gated PAM account/session are Phase 4.

## Ambiguity resolved

The roadmap mentions an explicit prevalidated PAM entry in Phase 1. This task
more strictly requires that prevalidated structures cannot start a login before
successful validation exists. Phase 1 therefore defines opaque types and
defers the callable PAM entry to Phase 4.
