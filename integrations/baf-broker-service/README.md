# BAF Assertion Issuance Service (broker-to-XRDP connector)

The network daemon that connects broker-side policy to XRDP: it exposes
the mutual-TLS issuance API consumed by the OpenUDS transport plugin
(`integrations/openuds-baf/`) and any other authorized broker front
end, applies the broker's authorization policy, signs BAF assertions
with the issuer key, and returns them to the caller. It completes the
chain:

```text
portal (Keycloak SSO) ─> OpenUDS + BAFRDP plugin
                              │ POST /v1/assertions   (mutual TLS)
                    baf_issuance_service.py  ← this component
                              │ signed BAF assertion
        plugin ─stdin/SSH or socket─> Handle service ─> XRDP validates
```

Single-file stdlib daemon (`http.server` + `ssl`); signing reuses
`broker-auth/reference-issuer/broker_issuer.py` (PyJWT + schema
validation), so issued assertions are exactly the profile XRDP's
validator and the conformance vectors expect.

## Trust and security model

- **Mutual TLS is mandatory.** Clients must present a certificate
  issued by `client_ca` *and* carry a CN listed in
  `allowed_client_cn`; everything else is denied. TLS ≥ 1.2.
- The TLS client (e.g. the OpenUDS server) is trusted to have
  authenticated the portal user upstream (Keycloak). This service still
  enforces the broker policy: unknown users, unknown targets, and
  targets outside the user's allowlist are denied (403, no detail).
- The **BAF signing key never leaves this host**; assertions are never
  logged (audit lines carry user, target, client CN, and `jti` only).
- Lifetimes are bounded (30–300 s, default 120), request bodies capped
  at 8 KiB, and a per-client-CN rate limit applies. Every anomaly fails
  closed.
- `issuer`/`kid` must match the XRDP hosts' `sesman.ini`
  `[BrokerAuth]` settings, and the signing key must pair with the
  deployed `TrustAnchor`.

## Deploy

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin baf-issuer
sudo mkdir -p /opt/xrdp-baf /etc/xrdp-baf/issuanced
sudo cp integrations/baf-broker-service/baf_issuance_service.py /opt/xrdp-baf/
sudo cp -r broker-auth/reference-issuer /opt/xrdp-baf/   # signing library
sudo cp integrations/baf-broker-service/config.example \
        /etc/xrdp-baf/issuanced/config                   # then edit
sudo cp integrations/baf-broker-service/policy.example.json \
        /etc/xrdp-baf/issuanced/policy.json              # then edit
sudo cp integrations/baf-broker-service/xrdp-baf-issuanced.service \
        /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now xrdp-baf-issuanced
```

Python dependencies (same as the reference issuer): `python3-jwt`,
`python3-cryptography`, `python3-jsonschema`. When installing outside
the repo layout, keep `reference-issuer/` importable (the service adds
`../../broker-auth/reference-issuer` relative to itself, so mirror that
layout or extend `PYTHONPATH` in the unit).

TLS material under `/etc/xrdp-baf/issuanced/` (root-owned; keys 0600):
server certificate/key, the CA bundle for client certificates, and the
BAF signing key (generate with
`broker_issuer.py keygen`). Give the OpenUDS server a client
certificate with the CN configured in `allowed_client_cn`, and point
the BAFRDP transport's "Broker issuance URL" at this service.

## API

`POST /v1/assertions` — request/response as documented in
`integrations/openuds-baf/README.md`. Responses: `200` with
`{"assertion": ...}`, `400` malformed, `403` denied, `404` unknown
path, `429` rate-limited, `500` internal. `GET /healthz` for liveness
(also mTLS-gated).

## Policy synchronization

The policy file is hot-reloaded: the service re-reads it whenever its
mtime/size changes, so grants apply without a restart. A file that
fails to parse keeps the last good policy in force (a partial write
must not turn into a fleet-wide outage); a bad policy at startup still
refuses to serve.

`uds_policy_sync.py` keeps the policy aligned with OpenUDS: it reads
the assigned user services from the OpenUDS admin REST API (who owns
which machine), builds the corresponding `policy.json`, and replaces it
atomically. Run it from a systemd timer or after assignment changes:

```sh
uds_policy_sync.py --config /etc/xrdp-baf/issuanced/policy-sync.config
uds_policy_sync.py --config ... --dry-run     # inspect without writing
```

See `policy-sync.config.example`. Safeguards: entries with names that
would fail the service's validation are skipped with a warning; a sync
that produces zero users refuses to overwrite a non-empty policy
unless `--allow-empty` is given; the REST paths are configurable to
absorb OpenUDS version differences. The sync account needs read-only
access to service pools; its password lives in a root-owned file, never
on the command line.

## Tests

```sh
python3 -m pytest integrations/baf-broker-service/tests
```

The suite generates ephemeral certificates, starts the real service,
and drives it with the OpenUDS plugin's `BrokerClient` — proving the
two components against each other over live mutual TLS, including CN
allowlisting, handshake rejection, policy denials, and signature/claims
verification of the issued assertion.
