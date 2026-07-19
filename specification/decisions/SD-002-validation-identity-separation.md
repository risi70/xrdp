# SD-002 — Separation of Assertion Validation and Linux Identity Binding

**Status:** Accepted
**Applies to:** BAF 1.0

## Decision

The BAF assertion validator is responsible only for cryptographic validation,
claim validation, target binding, assertion-level policy prechecks, and atomic
replay reservation. It MUST NOT perform system NSS, PAM, or external directory
identity lookups.

After successful validation, the validator returns a validated broker
capability containing canonical assertion metadata. This capability proves
that the broker assertion is authentic, fresh, correctly targeted,
assertion-policy-compatible, and non-replayed. It is not login authorization
and MUST NOT, by itself, authorize or start a Linux session.

Linux identity binding is a separate mandatory stage. Before PAM account or
session processing and before session creation, the implementation MUST
resolve and canonicalize the asserted preferred username through system NSS and
reject unknown, disabled, ambiguous, unauthorized, or policy-denied
identities. Only this later path may produce a resolved Linux login identity.

Phase 2 implements assertion validation and replay protection only. Phase 4a
implements system NSS identity binding and PAM preconditions. Phase 4b owns live
session activation after those prerequisites pass.

Once validation reserves an assertion, it is single-use until replay expiry.
A later identity-binding, authorization, PAM, or session-creation failure does
not permit retry. A `released` state is an audit marker only and does not make
the assertion reusable. Transient-failure retry is outside the MVP.

## Normative requirements

| ID | Requirement |
|---|---|
| SD2-001 | The assertion validator MUST NOT perform local or directory identity lookup. |
| SD2-002 | A validated broker capability MUST NOT be treated as session authorization. |
| SD2-003 | Linux identity binding through system NSS is mandatory before PAM account/session processing or session creation. |
| SD2-004 | A reserved assertion MUST remain unusable until expiry after later-stage failure; a `released` marker MUST NOT permit retry. |

The NSS data source is host policy, not BAF policy. LDAP provisioning or
synchronization, SSSD configuration or availability, Active Directory,
Kerberos, domain join, and Microsoft Entra are outside this decision and are
not BAF prerequisites.
