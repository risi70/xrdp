# FreeRDP Assertion Injection Notes

Mode B needs a southbound RDSAAD-capable client inside the gateway. A patched or
test-configured FreeRDP 3.x client may be useful for interoperability testing if
it can send an Authentication Request containing `rdp_assertion`.

This is an optional MS-RDPBCGR-compatible envelope test. Stock AAD/Entra
support does not cause FreeRDP to emit a broker-neutral BAF assertion.

This repository does not require a FreeRDP plugin for endpoint clients, and it
does not add a FreeRDP dependency to XRDP core. These notes are for gateway-side
lab work only.

Required test behavior:

- negotiate RDSAAD with XRDP;
- carry the exact BAF compact assertion as `rdp_assertion`;
- fail closed if Authentication Result is not `S_OK`;
- never fall back to username/password assertion transport;
- never log raw assertions.

If FreeRDP cannot be configured safely for this behavior, use another
gateway-side RDSAAD-capable client implementation. This only changes the
gateway's optional southbound role; it does not resolve SD-008 versus proposed
SD-009 or displace Broker-RDP Handle.
