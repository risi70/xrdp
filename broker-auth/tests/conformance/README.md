# Broker assertion conformance tests

The suite is independent of XRDP core. It verifies RS256 signatures and the
broker assertion profile's issuer, audience, time, target, JTI and username
requirements.

Run from the repository root:

```sh
python3 -m pip install -r broker-auth/tests/conformance/requirements.txt
python3 -m pytest broker-auth/tests/conformance
```
