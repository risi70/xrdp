# SD-006 — One-time server-side assertion handles for standard RDP broker compatibility

## Decision

BAF permits one-time server-side assertion handles for MVP broker ingress. A handle MAY travel in standard RDP broker-compatible routing or preconnection material where available, but MUST NOT contain the BAF assertion. It is a random, high-entropy, short-lived, single-use opaque lookup key—not login authorization or a bearer identity credential. The full assertion remains server-side and is resolved only by a trusted assertion-handle service or broker-side ingress component. Resolution MUST atomically consume the handle.

A handle has at least 128 bits of entropy (the implementation generates 256 bits), uses URL-safe/base64url or hex encoding, normally lives 30–120 seconds, and is bound to the target/local endpoint and broker correlation/session metadata where available. It is never reused across targets or accepted after expiry or first resolution.

Resolution fails closed when a handle is unknown, expired, consumed, malformed, target-mismatched, or the service is unavailable. Persistent, reusable, client-managed, and assertion-containing handles remain forbidden. Only short-lived, one-time, server-side handles are permitted.

The store keeps full assertions only in server memory, bounds handle count, assertion/request/response size and lifetime, never logs raw assertions, clears them after consume/expiry, and fails closed on storage or resolution errors. Effective validator and in-band transport limits still apply.

Trusted RDP proxy/fd-handoff and custom endpoint client/plugin transports remain deferred. UDS is a future Phase 5 reference broker and is not part of this generic MVP implementation.

## Related decision

SD-007 defines target mismatch as a consuming failure for known handles: no assertion is returned, the handle is invalidated, and later correct-target resolution cannot recover the assertion.
