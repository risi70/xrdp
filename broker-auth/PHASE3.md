# Phase 3: broker assertion transport scaffolding

Phase 3 adds a build-gated, broker-neutral transport object and distinct SCP
and EICP version-1 message codecs. Assertions are byte strings with explicit
lengths, an origin label, client address, and local target. The transport object
has a defensive 64 KiB allocation ceiling, but this is not the usable in-band
SCP/EICP assertion limit. The object owns its copy. Clearing it overwrites the
assertion before
freeing it, and message input/output buffers are marked for erasure.

`baf_transport_validate()` is the controlled handoff to the Phase 2 provider.
It always destroys raw assertion material after the provider returns. Provider
success is translated to
`BAF_TRANSPORT_VALIDATED_IDENTITY_BINDING_REQUIRED`, which deliberately cannot
be mistaken for login or session authorization. The returned capability holds
canonical metadata only.

The SCP capability bit and SCP/EICP broker request codecs are scaffolding for
the later production state-machine connection. No RDP field, username, or
password is overloaded. Runtime broker mode has no enabled production default;
the test transport must opt in explicitly.

Not implemented in this phase: Linux identity binding, NSS/SSSD lookup, PAM
account/session work, access policy, or session startup. Phase 4a resolves a
validated capability to an allowed Linux identity and completes the mandatory
PAM lifecycle before any successful login response or session creation.

Run the focused suite with:

```sh
./configure --disable-rfxcodec --enable-broker-auth
make -j2
make -C tests/baf check
python3 tests/baf/test_security_contract.py
```

`test_baf_transport` loads the committed Phase 2 vectors with their fixed
clock, exercises valid, invalid, replay, disabled-runtime, size, and lifecycle
paths through the actual C JWT provider, and never prints token material.
The current libipm message ceiling is nominally 8 KiB including framing. Under
SD-003, Phase 4b derives a lower exact assertion boundary and enforces the
minimum of validator, transport, and framed payload limits. The validator's
16 KiB default is not an in-band guarantee. MVP transport has no fragmentation,
no generic out-of-band handles, and no implicit libipm size increase. SD-006
one-time server-side assertion handles are the only permitted handle mechanism.
