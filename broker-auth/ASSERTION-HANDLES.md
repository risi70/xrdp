# Server-side assertion handles

`xrdp-baf-handled` is the Phase 4b-1 host-local assertion-handle authority. It listens only on a configurable Unix-domain `SOCK_SEQPACKET` socket (default `/run/xrdp/baf-handle.sock`, mode `0660`), never TCP. Trusted broker ingress stores an assertion and target with an expiry; the service generates a 256-bit random hex handle. A standard RDP broker may give only that opaque handle to the endpoint.

Resolution checks syntax, expiry, and target. A known unexpired handle is consumed or invalidated by the first resolve attempt that reaches the trusted service. If the target matches, the service atomically removes the entry and returns assertion bytes once to the trusted local BAF validation path. If the target mismatches, the service consumes the handle, returns no assertion bytes, clears the stored assertion, and later correct-target attempts fail. One concurrent resolver succeeds. Unknown, expired, consumed, malformed, target-mismatched, oversized, over-lifetime, capacity, IPC, and service failures fail closed. Assertions are cleared on consume, target mismatch, and expiry and are never logged.

The handle service and replay service are separate: the former temporarily stores assertions; `xrdp-baf-replayd` remains digest-only. Resolution and assertion validation are not login authorization. Phase 4b-1 stops before identity binding, PAM, or session startup.

The MVP does not support generic out-of-band assertion handles. The only permitted handle mechanism is SD-006: short-lived, one-time, server-side assertion handles used for standard RDP broker compatibility. These handles do not contain assertions and are resolved only by the trusted server-side assertion-handle service. Persistent, reusable, client-managed, assertion-containing, and generic bearer handles remain forbidden.

SD-007 defines target mismatch as a consuming failure: target mismatch never returns the assertion, invalidates the known handle, and prevents later recovery with the correct target. This is required for one-time semantics and probing resistance.

This preserves ordinary IGEL/RDP clients: no custom client, helper, DVC plugin, endpoint assertion handling, or username/password overloading is used. It also adds no UDS/Keycloak behavior, fd-handoff proxy, fragmentation, or live activation.
