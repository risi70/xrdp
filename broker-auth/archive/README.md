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

## Why these were superseded

The project evolved through three ingress designs. The endpoint-side RDSAAD
tracks (**Mode A** native client, **Mode B** broker gateway) and the earlier
assertion-handle notes were replaced by **Mode C** — now called **Broker-RDP
Handle** (SD-009) — which authorizes stock, unmodified RDP clients via a
single-use server-side handle. ("Mode C" survives as the code/config codename;
see [`../BROKER-RDP-HANDLE.md`](../BROKER-RDP-HANDLE.md) § "Naming".) The
phase notes (PHASE-1 … PHASE-5) are point-in-time development logs; the current
phase/roadmap view lives in
[`../../specification/10-roadmap.md`](../../specification/10-roadmap.md).

| Archived doc(s) | Superseded by |
|---|---|
| `PHASE-1.md` … `PHASE5.md` | `specification/10-roadmap.md` |
| `MODE-A-NATIVE-RDSAAD.md`, `MODE-B-GATEWAY-RDSAAD.md` | `BROKER-RDP-HANDLE.md` (SD-009) |
| `RDSAAD-INGRESS.md`, `RDSAAD-PREMCS-BRIDGE.md`, `RDSAAD-INTEGRATION-FOUNDATION.md` | Mode C ingress; `specification/decisions/SD-009-*` |
| `ASSERTION-HANDLES.md` | SD-006/SD-007 handle semantics as realized in Mode C |
| `IGEL-RDP-BROKER-FLOW.md`, `INTEROPERABILITY-TEST-PLAN.md` | `DEPLOYMENT-IGEL-UDS-PROXMOX.md`, `specification/07-testing-strategy.md` |
| `DEPLOYMENT.md`, `UDS-IGEL-UBUNTU-INTEGRATION-GUIDE.md` | `DEPLOYMENT-IGEL-UDS-PROXMOX.md` |

Full revision history for every file is preserved in git.
