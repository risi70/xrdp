# SD-007 — Target-mismatched handle resolution consumes the handle

## Decision

A target-mismatched assertion-handle resolution attempt MUST consume or invalidate the handle when the request reaches the trusted handle service and names a known, unexpired, unconsumed handle. The handle MUST NOT remain usable after that resolve attempt.

If the target matches, the assertion is returned once to the trusted local BAF validation path and the handle is consumed. If the target mismatches, the assertion is not returned, the stored assertion is cleared, and the handle becomes unusable. Subsequent attempts with the correct target MUST fail as consumed, not found, expired, or otherwise invalid; they MUST NOT recover the assertion.

Unknown or malformed handles do not create state, but they still fail closed. Expired handles fail closed and are cleaned or marked expired.

## Rationale

Consuming on target mismatch prevents target-probing attacks, repeated handle guessing or probing, and ambiguity over whether a failed resolve was a safe non-use. This preserves SD-006 one-time semantics and aligns target mismatch with fail-closed behavior.

## Scope

This decision applies only to SD-006 short-lived, one-time, server-side assertion handles. It does not permit generic out-of-band bearer handles, persistent handles, reusable handles, client-managed handles, assertion-containing handles, fragmentation, RDP proxy/fd-handoff, or live Phase 4b-2 session activation.
