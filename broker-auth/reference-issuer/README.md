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

Generate valid and invalid interoperability vectors:

```sh
python3 broker_issuer.py vectors --output-dir ../tests/vectors
```

Private keys are generated locally and are never written to the vector
directory. The vector public key is safe to distribute.
