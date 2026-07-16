# Archived BAF documents (superseded — historical only)

These documents record **earlier BAF design tracks and phase-by-phase
development notes** that have been superseded. They are kept for provenance but
are **not** current and should not be used to deploy or understand the shipped
system. For anything current, see:

- **Architecture:** [`../../BAF-ARCHITECTURE.md`](../../BAF-ARCHITECTURE.md) and
  the normative [`../../specification/`](../../specification/) set.
- **Shipped ingress:** [`../BROKER-RDP-HANDLE.md`](../BROKER-RDP-HANDLE.md)
  (SD-009 Track 1 — one-time server-side handle; stock RDP clients).
- **Deployment:** [`../DEPLOYMENT-IGEL-UDS-PROXMOX.md`](../DEPLOYMENT-IGEL-UDS-PROXMOX.md).

> **Not everything here stayed archived.** The RDSAAD design docs
> (`MODE-A-NATIVE-RDSAAD.md`, `MODE-B-GATEWAY-RDSAAD.md`,
> `RDSAAD-INTEGRATION-FOUNDATION.md`, `RDSAAD-PREMCS-BRIDGE.md`) and `PHASE5.md`
> were **moved back to the active tree** (`../`): the RDSAAD pre-logon exchange
> is still implemented as a secondary ingress alongside Broker-RDP Handle, and
> the `tests/baf` contract tests reference these documents — so the active tree
> must not depend on `archive/`.

## Why these were superseded

The project evolved through three ingress designs. The endpoint-side RDSAAD
tracks (**Mode A** native client, **Mode B** broker gateway) were **de-primed**
in favour of **Mode C** — now called **Broker-RDP Handle** (SD-009), which
authorizes stock, unmodified RDP clients via a single-use server-side handle —
but RDSAAD remains implemented, so its docs are active (see the note above).
("Mode C" survives as the code/config codename; see
[`../BROKER-RDP-HANDLE.md`](../BROKER-RDP-HANDLE.md) § "Naming".) The remaining
phase notes (PHASE-1 … PHASE4B) are point-in-time development logs; the current
phase/roadmap view lives in
[`../../specification/10-roadmap.md`](../../specification/10-roadmap.md).

| Archived doc(s) | Superseded by |
|---|---|
| `PHASE-1.md` … `PHASE4B.md` | `specification/10-roadmap.md` |
| `RDSAAD-INGRESS.md` | Broker-RDP Handle ingress; `specification/decisions/SD-009-*` |
| `ASSERTION-HANDLES.md` | SD-006/SD-007 handle semantics as realized in Broker-RDP Handle |
| `IGEL-RDP-BROKER-FLOW.md`, `INTEROPERABILITY-TEST-PLAN.md` | `DEPLOYMENT-IGEL-UDS-PROXMOX.md`, `specification/07-testing-strategy.md` |
| `DEPLOYMENT.md`, `UDS-IGEL-UBUNTU-INTEGRATION-GUIDE.md` | `DEPLOYMENT-IGEL-UDS-PROXMOX.md` |

Full revision history for every file is preserved in git.
