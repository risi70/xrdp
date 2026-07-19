# Broker-RDP Handle smoke tests

This directory contains focused integration proofs for Broker-RDP Handle.

- `run-local-proof.sh` exercises assertion issuance, handle registration,
  single-use resolution, nonce binding, and trusted replay using separate
  daemon processes. It does not require an RDP client or desktop session.
- `rdp-smoke.sh` runs on a prepared integration VM and checks the routing-token
  and one-time-credential ingress paths with a real XRDP desktop session.
- `baf_handle_tool.c` is the test-only registration and validation helper used
  by both scripts.

Build XRDP with `--enable-broker-auth` before running either proof. The VM test
also requires root, NSS/PAM test-user configuration, Xorg, and `xfreerdp`.
