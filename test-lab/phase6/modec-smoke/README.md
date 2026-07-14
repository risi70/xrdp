# Broker-RDP Handle smoke test (SD-009 Wave 1)

End-to-end verification of the Broker-RDP Handle ingress: the broker
registers a BAF assertion server-side and the client carries only a
single-use handle. Two parts, split by what each needs to run.

## Part A — headless local proof (`run-local-proof.sh`)

Runs anywhere the tree is built (`--enable-broker-auth`) with `python3` +
the reference-issuer deps (`pyjwt`, `cryptography`). No RDP client, X server,
PAM or root required. It exercises the real trusted daemons and real crypto:

```
reference issuer -> fresh nonce-bound assertion
  -> real xrdp-baf-replayd + xrdp-baf-handled (separate processes)
  -> register (handle) -> resolve+consume -> BAF validator
     (RequireNonceBinding, real replay service)
```

Checks:
- **positive** — a fresh nonce-bound assertion validates and yields the
  expected `preferred_username`;
- **negative 1** — a wrong `ts_nonce` is rejected (`RequireNonceBinding`);
- **negative 2** — a consumed handle cannot be reused (single-use);
- **negative 3** — a reused assertion (same `jti` behind a new handle) is
  rejected by the replay service — replay protection binds to the assertion
  identity, not the handle.

```bash
./run-local-proof.sh
# ... SMOKE PASS: Broker-RDP Handle headless proof succeeded (positive + 3 negatives)
```

This is the automated, reproducible proof of the handle-service + replay-
service + validator + nonce-binding integration. The `test_modec_live` case
in `tests/baf` covers the same daemon integration with the committed
fixed-time vector and runs under `make check`.

## Part B — RDP-level smoke test (`modec-smoke.sh`)

Runs **on the Phase 6 Ubuntu VDI VM as root**, with this xrdp build
installed and a real local test user. It drives an actual `xfreerdp` client
against the live `xrdp`/`xrdp-sesman`, covering the two ingress channels that
need root, PAM, NSS, an X server and TLS:

- **Channel 1 — routing token:**
  `xfreerdp /load-balance-info:"Cookie: msts=<handle>"` — the handle rides
  the X.224 routing token, no credential fields, authorized pre-MCS.
- **Channel 2 — one-time credential:**
  `xfreerdp /u:<user> /p:<handle>` — the handle-shaped password is consumed
  by Broker-RDP Handle and never reaches the PAM password stack.

For each channel it mints a fresh assertion for the test user, registers it
to obtain a handle, connects, and asserts a desktop session starts for the
NSS-resolved user. The script configures `[BrokerAuth]` Broker-RDP Handle settings and
the xrdp.ini keys itself, so it works before the C6 broker integration
exists.

```bash
sudo LAB_TEST_USER=bafuser ./modec-smoke.sh
```

Run it via the lab from the Ansible controller:

```bash
cd test-lab/kvm/ansible
ansible-playbook -i inventory.ini playbooks/verify.yml --tags modec-smoke
```

## Part C — Smart-card broker authentication (card → broker → Broker-RDP Handle)

Verifies a full **card → broker → session** flow. A virtual smart card — a
PIN-protected PKCS#12 credential — authenticates the user to the reference
broker by X.509 challenge-response (proof of possession). The broker
validates the certificate chain to a trusted CA, maps the certificate
identity to a Linux user, mints a BAF assertion, and registers a one-time
handle, which then rides the proven Broker-RDP Handle path to a desktop session.

xrdp has no server-side NLA/CredSSP, so the smart card authenticates to the
**broker** (northbound), not to the RDP connection itself.

- **`run-smartcard-proof.sh`** (anywhere): headless proof — trusted card
  authenticates and its assertion validates through the real daemons;
  untrusted-CA and expired cards are rejected by the broker.
  ```bash
  ./run-smartcard-proof.sh
  # ... SC PROOF PASS: smart-card -> broker -> handle -> validate (positive + 2 negatives)
  ```
- **`smartcard-smoke.sh`** (VDI VM, root): a virtual smart card drives both
  Broker-RDP Handle channels to a real desktop session for the NSS-resolved user.
  ```bash
  cd test-lab/kvm/ansible
  ansible-playbook -i inventory.example.ini playbooks/verify.yml --tags smartcard-smoke
  ```

The card backend is pluggable (`broker-auth/reference-broker/smartcard_auth.py`):
`P12Card` signs directly with the p12 key (used by `smartcard-smoke.sh`);
`Pkcs11Card` drives a real PKCS#11 token (SoftHSM2 loaded from the same p12)
via `pkcs11-tool` for higher fidelity — `smartcard_login.py` accepts either
via `--p12` or `--pkcs11-module/--token-label/--card-cert`.

### SoftHSM2 token + card removal/reinsertion (`softhsm-smoke.sh`, VDI VM)

Higher-fidelity variant: the card is a real SoftHSM2 PKCS#11 token
provisioned from the bafuser p12, so the private-key operation goes through
the token. It then exercises the physical card lifecycle:

1. **inserted** — the token signs the broker challenge → assertion → handle
   → Broker-RDP Handle → desktop session;
2. **removed** — the token directory is moved out of the SoftHSM2 tokendir,
   so `pkcs11-tool` signing fails closed and the broker issues no assertion
   and no handle (access denied);
3. **reinserted** — the same token returns and a session starts again.

```bash
cd test-lab/kvm/ansible
ansible-playbook -i inventory.example.ini playbooks/verify.yml --tags softhsm-smoke
# ... HSM SMOKE PASS: SoftHSM2 card insert -> remove(deny) -> reinsert lifecycle verified
```

Requires `softhsm2` + `opensc` (installed by the `ubuntu_vdi_xrdp_baf` role).

## Files

| File | Runs on | Purpose |
|---|---|---|
| `run-local-proof.sh` | anywhere (built tree) | headless crypto/handle/replay proof |
| `modec-smoke.sh` | Phase 6 VDI VM (root) | xfreerdp routing-token + one-time-credential |
| `run-smartcard-proof.sh` | anywhere (built tree) | headless card → broker → handle → validate |
| `smartcard-smoke.sh` | Phase 6 VDI VM (root) | virtual smart card → broker → Broker-RDP Handle session |
| `make-smartcard.py` | both | generate CA + user p12 (the simulated card) |
| `baf_handle_tool.c` | both | `store`/`check` CLI; C6 broker-registration stand-in |

Broker-side smart-card auth lives in
`broker-auth/reference-broker/smartcard_auth.py` + `smartcard_login.py`.
`baf_handle_tool` and the card material are lab helpers, not production
components — the broker registration path is SD-009 Wave 2 (C6).
