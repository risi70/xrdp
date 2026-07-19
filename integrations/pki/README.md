# BAF X.509 Key Setup

`baf-pki-setup.sh` implements the credential inventory of
`broker-auth/DEPLOYMENT-PKI-CREDENTIALS.md` (K1–K11) and emits one
ready-to-copy bundle per host, with a README in each bundle naming the
exact destination paths and configuration keys.

Two ways to obtain certificates:

```sh
# Lab: create a CA hierarchy standing in for the central PKI,
# then issue everything from it.
./baf-pki-setup.sh init-ca --out ca/
./baf-pki-setup.sh issue --ca ca/ --config pki.conf --out bundles/

# Central PKI: generate keys and CSRs only; submit the CSRs to the
# real issuing CAs and drop the returned certificates into the bundles.
./baf-pki-setup.sh csr --config pki.conf --out csr/
```

Copy `pki.conf.example` to `pki.conf` and set the FQDNs, VDI host
list, client CN, and `kid`.

What it produces (IDs from the credentials document):

- `broker/` — K1 signing pair + `kid` marker, K2 server cert/key,
  client CA bundle (`clients-ca.pem`).
- `uds/` — K3 mTLS client cert (CN = `allowed_client_cn`), K4 portal
  cert, K10 registration SSH keypair, broker CA bundle.
- `keycloak/` — K6 server cert/key.
- `vdi-<host>/` — K9 cert/key, the K1 public key as
  `baf-broker-public.pem` (TrustAnchor), and an
  `authorized_keys.snippet` with the forced `baf-uds-register` command
  already bound to that host's target name. Host-key pinning (K11) is
  a one-liner printed in each bundle README (`ssh-keyscan`).

Properties enforced by design and covered by the test suite
(`tests/`): the client certificate chains **only** through the
dedicated client-auth issuing CA (the issuance service's authorization
boundary), server certs carry correct SANs and EKUs, every private key
is created mode 0600 under `umask 077`, and the TrustAnchor byte-equals
the signing public key.

CAs are EC P-256; K1 is RSA-2048 because BAF assertions are RS256.
With Vault available (see the credentials document), skip `init-ca`
and use the PKI/SSH secrets engines instead — the bundle layout and
destination paths stay the same.
