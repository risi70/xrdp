# UDS Simulator Adapter

This adapter is a Phase 5 reference integration point for UDS-like broker
objects. It is deliberately a simulator rather than production UDS API code.

The adapter maps:

```text
UDS user/session/resource
-> BAF user/target/broker_session_id/auth_context
```

It does not modify or depend on XRDP core code. `libxrdp`, `xrdp`, `sesman`,
`sesexec`, `libipm`, the BAF validator, and the RDSAAD parser must remain
broker-neutral.

Production UDS integration can replace this simulator with an API-facing
adapter if the same broker-neutral contract is preserved.
