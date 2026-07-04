# Phase 2 — Assertion validator and replay core

Phase 2 adds a generic `auth_provider_jwt` implementation behind
`--enable-broker-auth`. It validates BAF compact JWS assertions and returns an
opaque validated broker capability only after atomic replay reservation. It
does not perform NSS/SSSD mapping, invoke PAM, alter SCP/EICP, or start a
session.

## Dependencies

Enabled builds require libjwt 1.15 or later, Jansson 2.7 or later, and the
existing OpenSSL dependency. Configure reports a targeted error when libjwt or
Jansson is absent. Disabled builds do not check or link these libraries.
libjwt verifies the received compact serialization; Jansson performs strict
header and claim parsing with duplicate-member rejection before policy
processing. No libjwt type appears in the provider interface.

## Trust and replay

The MVP trust loader accepts an administrator-selected local PEM public key
bound to one exact issuer and `kid`. RSA keys below 2048 bits and non-RSA keys
are rejected. Assertion-controlled `jku`, `x5u`, and `jwk` headers are always
rejected. Remote JWKS retrieval and local JWK-set loading remain isolated
future trust-loader backends; tokens can never select either location.

The memory replay backend hashes `UTF8(iss) || 0x00 || UTF8(jti)` with SHA-256,
uses a mutex-protected atomic insert-if-absent operation, has fixed capacity,
and expires entries at `exp + clock_skew`. It never receives or stores raw
assertions. Cache absence, exhaustion, and locking errors fail closed.

## Boundaries

The capability stores canonical assertion metadata and a JTI digest, not the
raw token. The temporary NUL-terminated copy required by libjwt is cleansed
after validation. Caller-owned assertion storage remains the caller's erasure
responsibility.

Phase 3 transports opaque assertions. Phase 4 binds
`preferred_username` through NSS/SSSD and integrates PAM account/session
processing. A Phase 2 capability alone has no session-start API.

## Tests

```sh
./bootstrap
mkdir build && cd build
../configure --disable-rfxcodec --enable-broker-auth
make -j2
make -C tests/baf check
make -C tests/sesman check
```

The optional fuzz harness and build example are under `tests/baf/fuzz/`.

## Deferred optional backends

SQLite replay and HTTPS JWKS are not linked in Phase 2. Adding either requires
the same atomic/fail-closed contract and separate optional dependency checks.
