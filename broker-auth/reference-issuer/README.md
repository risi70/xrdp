# Broker assertion reference issuer

This tool issues RS256 JWTs conforming to
`../spec/broker-assertion.schema.json`. It is a development and
interoperability reference, not a production identity provider.

Generate a key and issue an assertion:

```sh
python3 broker_issuer.py keygen \
  --private-key issuer-key.pem --public-key issuer-key.pub.pem

python3 broker_issuer.py issue \
  --private-key issuer-key.pem --kid reference-key \
  --issuer https://broker.example --audience xrdp-sesman \
  --subject user-123 --username alice \
  --group remote-desktop --role desktop-user \
  --target rdp-host.example --session-id session-123 \
  --auth-context '{"acr":"mfa","amr":["pwd","otp"]}'
```

Regenerate the deterministic Phase 2 conformance corpus from the repository
root:

```sh
python3 broker-auth/reference-issuer/generate_phase2_vectors.py
```

This writes:

- `broker-auth/vectors/phase2-vectors.json`
- `broker-auth/vectors/test-public.pem`

The generator uses the committed, test-only RSA key under `tests/baf/data/`
and a fixed validation clock (`1700000000`), so the corpus is reproducible.
That key MUST NOT be used outside tests. No private key is copied into the
vector directory. `broker-auth/vectors/test-public.pem` is the public half of
that key and is the issuer-bound trust anchor used by the native validator
test.

Phase 2 deliberately supports RS256 only. PS256 and ES256 are deferred until
algorithm agility can be implemented and tested completely; Phase 2 rejects
them.

Validate vector completeness and the static RS256 signature:

```sh
python3 -m pytest broker-auth/tests/test_phase2_vectors.py
```

Exercise every vector through the actual C provider after configuring an
enabled build:

```sh
make -C tests/baf check TESTS=test_phase2_vectors
```

The native test locates assets through Automake's `top_srcdir`, injects the
committed fixed validation time, checks each provider status exactly, and
proves that an audit-only replay release does not allow reuse. Regenerated
vectors must retain the fixed clock and remain byte-for-byte deterministic.
Runtime code must never log generated assertions or other raw token material.
