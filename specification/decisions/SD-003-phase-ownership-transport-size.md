# SD-003 — Phase Ownership and Assertion Transport Size

**Status:** Accepted

**Date:** 2026-07-05
**Applies to:** BAF 1.0 MVP

## Context

The original roadmap combined Linux identity binding, PAM integration, and live
session activation in Phase 4, while the completed implementation intentionally
stopped before live activation. Separately, the validator permits assertions up
to 16 KiB by default, but the current in-band libipm/SCP/EICP path has an 8 KiB total
message capacity, leaving less assertion space after protocol framing overhead. Treating the validation
ceiling as a transport guarantee would be unsafe.

## Decision

The completed implementation is reclassified as **Phase 4a — Linux Identity
Binding and PAM Preconditions**. Phase 4a consumes a validated capability,
binds `preferred_username` through NSS/SSSD-compatible APIs, rejects UID 0 by
default, establishes the prevalidated PAM account handle, and preserves classic
password/PAM behavior. Phase 4a does not authorize or start a live broker
session.

**Phase 4b — Live Broker-Auth Session Activation** is the next implementation
phase. It owns production state-machine wiring and may authorize session startup
only after assertion validation and replay reservation, capability creation,
NSS/SSSD identity binding, UID 0 rejection, PAM account approval, and the
required PAM credential/session lifecycle. Broker auth remains disabled at
build time and runtime by default.

**Phase 5 — Reference Broker and Interoperability** remains the reference
ecosystem phase. UDS Enterprise is a reference broker use case only and adds no
broker-specific requirement to XRDP core.

The MVP uses no assertion fragmentation and no out-of-band assertion handles.
For in-band SCP/EICP transport, the effective assertion maximum is:

```text
min(configured validator maximum,
    configured transport maximum,
    libipm/SCP/EICP payload capacity after framing overhead)
```

The default configured in-band transport ceiling is 8 KiB, but the usable
assertion boundary MUST be reduced by actual framing overhead. Every hop MUST
check its applicable bound before allocation or forwarding and fail closed on
oversize input. The validator's 16 KiB default is an upper validation bound,
not a guarantee that an in-band transport can carry a 16 KiB assertion.

## Normative requirements

| ID | Requirement |
|---|---|
| SD3-001 | The completed identity-binding/PAM-precondition implementation is Phase 4a and MUST NOT activate a live session. |
| SD3-002 | Phase 4b MUST own live activation and require every validation, replay, identity, UID, and PAM prerequisite. |
| SD3-003 | Phase 5 MUST remain reference broker and interoperability work with no reference-specific XRDP core logic. |
| SD3-004 | Effective in-band size MUST be the minimum of validator, transport, and framed payload limits. |
| SD3-005 | MVP in-band transport MUST fail closed on oversize input and MUST NOT fragment or use out-of-band handles. |

## Consequences

- Phase 4a is complete without claiming live session activation.
- Phase 4b has an explicit, testable authorization boundary.
- Implementations MUST derive and test the exact permitted in-band boundary;
  they MUST NOT assume the nominal 8 KiB message capacity is all assertion data.
- An assertion accepted by a direct validator API may still be correctly
  rejected by a stricter transport before validation.
- Oversize transport failures do not fall back to classic password login.

## Deferred work

Fragmentation, multi-message reassembly, out-of-band assertion handles, larger
libipm messages, and alternate transports are deferred beyond the MVP and
require a separate protocol/security decision.
