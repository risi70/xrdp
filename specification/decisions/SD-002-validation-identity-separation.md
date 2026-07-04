# SD-002 — Separation of Assertion Validation and Linux Identity Binding

**Status:** Accepted
**Applies to:** BAF 1.0

## Decision

The BAF assertion validator is responsible only for cryptographic validation,
claim validation, target binding, assertion-level policy prechecks, and atomic
replay reservation. It MUST NOT perform NSS, SSSD, PAM, LDAP, FreeIPA, Active
Directory, local `passwd`, or equivalent Linux identity lookups.

After successful validation, the validator returns a validated broker
capability containing canonical assertion metadata. This capability proves
that the broker assertion is authentic, fresh, correctly targeted,
assertion-policy-compatible, and non-replayed. It is not login authorization
and MUST NOT, by itself, authorize or start a Linux session.

Linux identity binding is a separate mandatory stage. Before PAM account or
session processing and before session creation, the implementation MUST
resolve and canonicalize the asserted preferred username through NSS/SSSD and
reject unknown, disabled, ambiguous, unauthorized, or policy-denied
identities. Only this later path may produce a resolved Linux login identity.

Phase 2 implements assertion validation and replay protection only. Phase 4
implements NSS/SSSD identity binding and PAM account/session integration.

Once validation reserves an assertion and produces a capability, the
assertion is single-use by default. A later identity-binding, authorization,
PAM, or session-creation failure SHOULD leave the reservation consumed. A
bounded release policy MAY apply only to explicitly classified transient
infrastructure failures; the MVP default is fail-closed and consume-once.

## Normative requirements

| ID | Requirement |
|---|---|
| SD2-001 | The assertion validator MUST NOT perform local or directory identity lookup. |
| SD2-002 | A validated broker capability MUST NOT be treated as session authorization. |
| SD2-003 | Linux identity binding through NSS/SSSD is mandatory before PAM account/session processing or session creation. |
| SD2-004 | A replay reservation SHOULD remain consumed after later-stage failure; bounded release is permitted only for explicitly classified transient infrastructure failure. |
