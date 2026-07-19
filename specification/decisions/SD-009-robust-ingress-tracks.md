# SD-009 — Robust ingress tracks and buildable missing components

**Status: PROPOSED (draft for review — not yet accepted)**

**Implementation status:** Wave 1 (C5 + C3) is implemented on this branch:
nonce plumb-through with `urn:baf:ts_nonce`/`RequireNonceBinding`, the Broker-RDP Handle
one-time-credential PAM path, and the Broker-RDP Handle routing-token pre-MCS ingress.
See `broker-auth/BROKER-RDP-HANDLE.md`.

## Context

SD-008 selected RDSAAD-style pre-logon assertion ingress as the MVP path. The
XRDP-side implementation is complete and fail-closed, but the client side is
unproven: no stock RDP client can emit a BAF-profile `rdp_assertion`. Real
RDSAAD clients (mstsc `enablerdsaadauth`, FreeRDP 3 AAD) emit Entra
proof-of-possession assertions signed with an ephemeral client key and bound to
`ts_nonce`; these can never satisfy the BAF 1.0 schema, and BAF assertions can
never satisfy an Entra-validating server. RDSAAD ingress is therefore
*wire-shaped* interoperability, not client interoperability.

SD-009 keeps RDSAAD as the validator-facing ingress contract, treats SD-008 as
elegant but not definitive, and admits developing missing components as part of
the solution space. **Server-side and proxy-side components are prioritized**:
they are under this project's deployment control, while endpoint clients (IGEL
in particular) are locked down and require vendor cooperation to change.
Client-side components remain in the solution space but are deferred.

External precedent surveyed (2026-07):

- **oVirt / Proxmox / OpenUDS**: broker-issued one-time tickets, bound to
  destination and expiry, delivered as the connection password or launch
  parameter. The dominant non-cloud-native FOSS VDI pattern; entirely
  server/broker-side, works with stock clients.
- **Apache Guacamole `guacamole-auth-json`**: broker-signed+encrypted
  connection descriptor delivered server-side; the client holds only an opaque
  session reference.
- **Devolutions Gateway / IronRDP**: RDP relay authorized by a broker-signed
  RS256 JWT; RDCleanPath PDU avoids a redundant TLS layer at the splice point.
- **rdpgw (bolkedebruin)**: open-source MS-TSGU (RD Gateway) in Go; OIDC login
  mints a short-lived JWT in the `.rdp` `gatewayaccesstoken`; stock
  mstsc/FreeRDP/IGEL clients reach it natively over HTTPS.
- **FreeRDP 3 `aad.c`**: implements the complete RDSAAD connection sequence
  with a `GetAccessToken` callback seam; only token acquisition and
  PoP-assertion construction are Entra-specific. Relevant to the deferred
  client track and as implementation reference for the gateway's southbound
  RDSAAD client role.
- **Teleport Desktop Access**: per-connection ephemeral certificates with a
  5-minute TTL; adopts nothing directly but sets the issuance discipline.

## Decision

BAF pursues three ingress tracks, in server-first priority order, each backed
by named buildable components. All tracks feed the unchanged Phase 4
authorization chain (BAF JWT validator → trusted replay → NSS/SSSD identity
binding → UID 0 rejection → PAM preconditions → `AllowSessionStart` gate).
XRDP core stays broker-neutral.

### Track 1 (primary, server-side): revive SD-006 handles as Broker-RDP Handle

Stock, unmodified clients get a working path through changes confined to
xrdp/sesman and the broker side:

- **C3 — Broker-RDP Handle resolution hooks (xrdp/sesman).** (a) Handle acceptance from
  X.224 routing token / FreeRDP `/pcb:` preconnection material, and (b) a
  one-time-credential path through the existing sesman PAM auth flow (handle
  as single-use password), both resolving through the existing
  `baf_handle_service`, which is promoted from superseded to production
  status.
- **C5 — Nonce plumb-through (xrdp/sesman).** `xrdp_sec_rdsaad_exchange()`
  retains the generated nonce and passes it in `request.server_nonce` through
  SCP/EICP to the validator instead of erasing it unused. BAF 1.0 gains an
  optional extension claim `urn:baf:ts_nonce`; when the deployment sets
  `RequireNonceBinding=true`, assertions missing or mismatching the nonce
  fail closed. Small now, load-bearing for Track 2.
- **C6 — OpenUDS transport plugin (broker side).** A UDS transport that
  registers the assertion with the handle service over a trusted channel
  (root-owned socket locally, mTLS across hosts), receives the handle, and
  launches the client with the right parameters. Lives in the broker's tree,
  mirroring the Phase 5 adapter boundary.

Broker-RDP Handle profile: registration runs the **full BAF validator and replay
reservation immediately** (no handle for invalid assertions); handles are
256-bit, base64url/hex, TTL 30–120 s, target-bound, atomically consumed
(SD-007 unchanged). Broker-RDP Handle is exempt from nonce binding; its freshness comes
from registration-time reservation plus handle TTL.

Amendments required: AST-015 and SD-008 language is narrowed — the prohibition
remains on *generic, reusable, client-managed, or assertion-containing*
handles and on placing the **assertion** in username/password fields. A
single-use SD-006 handle is not the assertion and is permitted in the routing,
preconnection, and one-time-credential channels.

### Track 2 (proxy-side): Mode B as an RDCleanPath-style splice gateway

For deployments that reject credential-field or preconnection usage, or that
want RD Gateway-style HTTPS traversal, Mode B is built as:

- **C4 — Splice gateway (new component, proxy side).** Northbound accepts
  stock clients (plain RDP-over-TLS admission via a Track 1 handle or broker
  ticket; optionally MS-TSGU transport by reusing/forking `rdpgw` so
  unmodified IGEL/mstsc clients traverse HTTPS). Southbound performs the
  RDSAAD exchange with XRDP using a fresh nonce-bound assertion fetched from
  the broker after `ts_nonce` arrives, then splices northbound and southbound
  TLS legs at the MCS boundary (Devolutions RDCleanPath pattern). Candidate
  base: IronRDP (Rust) for the southbound client role. The gateway never
  handles Linux credentials; XRDP remains the sole authorization authority.

The gateway's southbound module doubles as the **RDSAAD wire-level
conformance client** for the Phase 6 lab, removing the currently skipped
stock-client wire test without any endpoint change: `C4-south` alone,
exercised against the live bridge with `RequireNonceBinding=true`, proves
SD-008 end-to-end.

### Track 3 (deferred, client-side): FreeRDP assertion provider

Retained in the solution space for deployments that *can* ship client
software, but explicitly not on the critical path:

- **C1 — FreeRDP external-assertion provider patch**: a configuration-gated
  option in FreeRDP 3's AAD path that, on Server Nonce receipt, invokes an
  external provider with `ts_nonce` and target and sends the returned compact
  JWS verbatim as `rdp_assertion`. Small; designed for upstreaming.
- **C2 — Broker assertion helper**: client-side executable that presents a
  broker session ticket and returns a fresh nonce-bound BAF assertion.
- **C7 — IGEL Custom Partition packaging** of C1+C2; production IGEL adoption
  is a vendor-cooperation task.

Track 3 requires no XRDP-side changes beyond Track 1's C5; the server cannot
distinguish a Track 3 client from a Track 2 gateway southbound leg.

## Component inventory and sequencing

| ID | Component | Track | Side | Size | Home |
|---|---|---|---|---|---|
| C3 | Broker-RDP Handle hooks: pcb/routing-token + one-time-credential PAM path | 1 | server | M | xrdp/sesman |
| C5 | Nonce plumb-through + `urn:baf:ts_nonce` + `RequireNonceBinding` | 1/2 | server | S | xrdp/sesman |
| C6 | OpenUDS BAF transport plugin | 1 | broker | M | OpenUDS tree |
| C4 | Splice gateway (southbound RDSAAD client + splice; optional rdpgw northbound) | 2 | proxy | L | new repo |
| C1 | FreeRDP external-assertion provider option | 3 | client | S | FreeRDP fork → upstream PR |
| C2 | Broker assertion helper (client side) | 3 | client | S | broker integration |
| C7 | IGEL Custom Partition packaging of C1+C2 | 3 | client | M (non-code) | deployment |

Waves, server/proxy first:

- **Wave 1 (server only): C5 + C3.** Nonce plumb-through and Broker-RDP Handle hooks in
  this tree; handle service promoted to production. Stock `xfreerdp /pcb:`
  and one-time-credential logins become testable in the Phase 6 lab with zero
  client or proxy changes.
- **Wave 2 (broker + proxy): C6, then C4 starting with its southbound RDSAAD
  module.** The southbound module lands first as the lab's wire-level
  conformance client, then grows the northbound/splice roles into the full
  Mode B gateway.
- **Wave 3 (client, optional): C1 + C2 + C7** only where a deployment can
  ship endpoint software and prefers gateway-less nonce-bound Mode A.

## Consequences

- The critical path to a provable end-to-end system touches only this tree,
  the broker tree, and a new proxy component — no endpoint changes.
- SD-008's ingress is proven by the Track 2 southbound module rather than by
  waiting on client vendors; the currently skipped wire-level test becomes a
  required conformance test.
- The "no custom client / no FreeRDP plugin" requirement is amended from a
  hard prohibition to: *XRDP core MUST NOT require a specific client; stock
  clients MUST have a supported path (Broker-RDP Handle); patched/extended clients MAY
  be provided as optional deployment components.*
- The existing `baf_handle_service` code and tests are promoted from
  superseded to production status instead of being removed.
- Two additional ingress modes must be covered by conformance tests and kept
  fail-closed independently; runtime config gains Broker-RDP Handle enable flags and
  `RequireNonceBinding`.
- New out-of-tree deliverables (C4, C6; later C1/C2/C7) need their own repos,
  CI, and release discipline; XRDP core review boundaries are unchanged.

## Non-goals

- No assertion bytes in username/password/routing/preconnection fields
  (unchanged; handles are references, never assertions).
- No reusable or multi-use handles (unchanged).
- No Entra/Keycloak/UDS-specific behavior in XRDP core (unchanged; C6 lives
  in the OpenUDS tree, the gateway is broker-neutral).
- No replacement of the RDSAAD validator-facing contract; all tracks feed the
  same validation model.
- Server-side CredSSP/NLA with Kerberos is explicitly rejected for the MVP:
  XRDP has no server-side CredSSP, the implementation cost is very high, and
  it binds deployments to AD/KDC infrastructure without helping the
  IGEL/OpenUDS target environment.
