# Server-side assertion handles

`xrdp-baf-handled` is the Phase 4b-1 host-local assertion-handle authority. It listens only on a configurable Unix-domain `SOCK_SEQPACKET` socket (default `/run/xrdp/baf-handle.sock`, mode `0660`), never TCP. Trusted broker ingress stores an assertion and target with an expiry; the service generates a 256-bit random hex handle. A standard RDP broker may give only that opaque handle to the endpoint.

Resolution checks syntax, expiry, and target, then atomically removes the entry before returning assertion bytes to the trusted local BAF validation path. One concurrent resolver succeeds. Unknown, expired, consumed, malformed, target-mismatched, oversized, over-lifetime, capacity, IPC, and service failures fail closed. Assertions are cleared on consume and expiry and are never logged.

The handle service and replay service are separate: the former temporarily stores assertions; `xrdp-baf-replayd` remains digest-only. Resolution and assertion validation are not login authorization. Phase 4b-1 stops before identity binding, PAM, or session startup.

This preserves ordinary IGEL/RDP clients: no custom client, helper, DVC plugin, endpoint assertion handling, or username/password overloading is used. It also adds no UDS/Keycloak behavior, fd-handoff proxy, fragmentation, or live activation.
