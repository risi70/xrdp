# Trusted Replay Service

Phase 4b uses `xrdp-baf-replayd` as the host-local replay authority for SD-008 RDSAAD-style pre-logon assertions and any retained experimental handle path. Separate
`xrdp-sesexec` workers connect to its Unix-domain socket and submit only the
32-byte SHA-256 replay digest, expiry, operation, and an optional correlation
identifier. JWTs, usernames, and claims are neither transmitted nor stored.

## Runtime

The default endpoint is `${socketdir}/baf-replay.sock`, normally
`/run/xrdp/baf-replay.sock`. The daemon creates the socket with mode `0660`;
the service manager must run it with ownership shared by the XRDP/sesman
workers. Broker authentication fails closed when the endpoint is unavailable
or returns a malformed or indeterminate response. Classic password login does
not use this service.

Command-line controls are:

```text
xrdp-baf-replayd [-s socket] [-c maximum-entries] [-t maximum-ttl-seconds]
```

Defaults are 100000 entries, a 1020-second maximum TTL, and the socket above.
Live validator configuration must set `require_service_replay`; this rejects a
worker-local memory backend. The memory constructor remains available for unit
and single-process conformance tests only.

## Protocol and semantics

The local protocol uses fixed-size, versioned `AF_UNIX/SOCK_SEQPACKET`
messages. Operations are reserve, mark consumed, mark released, status,
cleanup expired, and ping. Reserve is atomic because one persistent process
owns the bounded table. Released is an audit marker and cannot be reserved
again before expiry.

Malformed, oversized, expired, unknown, capacity-exhausted, timed-out, or
unavailable requests fail closed. Raw assertions are never logged.

## Tests

Run:

```sh
./bootstrap
./configure --disable-rfxcodec --enable-broker-auth
make -C tests/baf check
```

`test_replay_service` starts a real service process and forks independent
workers. It proves exactly one same-key reservation, distinct-key success,
expiry cleanup, consume-once release behavior, malformed/oversized rejection,
and unavailable-service failure.

## Deferred work

Cluster-wide replay coordination, persistent daemon storage, SQLite/LMDB
behind the service interface, service-manager hardening, and distributed
broker replay remain deferred. Direct worker-local SQLite is not the selected
architecture.
