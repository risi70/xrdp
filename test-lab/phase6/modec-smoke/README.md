# Mode C smoke test (SD-009 Wave 1)

End-to-end verification of the Mode C one-time-handle ingress: the broker
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
# ... SMOKE PASS: Mode C headless proof succeeded (positive + 3 negatives)
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
  by Mode C and never reaches the PAM password stack.

For each channel it mints a fresh assertion for the test user, registers it
to obtain a handle, connects, and asserts a desktop session starts for the
NSS-resolved user. The script configures `[BrokerAuth]` Mode C settings and
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

## Files

| File | Runs on | Purpose |
|---|---|---|
| `run-local-proof.sh` | anywhere (built tree) | headless crypto/handle/replay proof |
| `modec-smoke.sh` | Phase 6 VDI VM (root) | xfreerdp routing-token + one-time-credential |
| `baf_handle_tool.c` | both | `store`/`check` CLI; C6 broker-registration stand-in |

`baf_handle_tool` is a lab helper, not a production component — the broker
registration path is SD-009 Wave 2 (C6).
