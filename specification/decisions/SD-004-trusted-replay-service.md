# SD-004 — Trusted Replay Service for Live Broker Authentication

Date: 2026-07-06

## Context

Each broker login is validated in a separate `xrdp-sesexec` process. A replay
table held in worker-local memory cannot atomically enforce consume-once use
across those processes.

## Decision

Phase 4b live activation requires a persistent, host-local trusted replay
service. Workers MUST reserve the digest of `(iss,jti)` through this service
before a validated capability can authorize a live session. The service uses
a local Unix-domain socket and performs atomic reserve-if-absent over one
bounded replay table.

Workers MUST NOT independently accept replay state from process-local memory.
Missing, unreachable, overloaded, corrupt, malformed, timed-out, or
indeterminate service responses fail broker authentication closed. Raw
assertions are never sent to or stored by the service.

The memory backend remains valid only for unit tests and explicitly isolated
single-process test harnesses. SQLite is not the Phase 4b production
architecture; a future revision may use it as private storage behind the
trusted service interface.

Phase 4b provides host-local cross-process protection only. Cluster-wide
replay prevention remains the broker's responsibility unless a distributed
replay service is specified later.

## Consequences

- Live activation requires a healthy replay service and restricted local
  socket.
- Service state is bounded by capacity and assertion expiry.
- `released` remains an audit marker and never enables reuse before expiry.
- Classic password authentication does not depend on the replay service.

## Deferred work

- Cluster-wide replay coordination.
- Persistent replay-service storage.
- SQLite or LMDB as an internal service implementation.
- Broker-side distributed replay enforcement.

## Status
