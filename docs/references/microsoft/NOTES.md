# Microsoft Notes

## MS-RDPESC (smart-card redirection) — for the chansrv `--enable-smartcard` tests

Reviewed revision 17.0 (2024-04-23). Wire facts used by
`tests/baf/test_smartcard_scard.c` and the fuzz target. Structures/IDL are
usable per the MS Open Specifications IP notice (code samples/IDL may be
reproduced in implementations).

- Server → client requests are Device Control Requests over `rdpdr`
  ([MS-RDPEFS]); the response `OutputBuffer` is an **RPCE type-serialized**
  structure (§3.2.5 / [MS-RPCE] 2.2.6): 8-byte common type header
  (version `0x01`, endianness `0x10`, header length `0x0008`, filler
  `0xCCCCCCCC`) + 8-byte private header (ObjectBufferLength, filler), then the
  NDR body with referent-id pointers for `[unique]` fields and a conformant
  array count preceding each `[size_is]` array. xrdp's parsers reach this buffer
  after `devredir` strips the 12-byte `DR_DEVICE_IOCOMPLETION` header, then read
  a 4-byte `OutputBufferLen`.
- IOCTL codes (§3.1.4), values used by `smartcard.c`:
  ESTABLISHCONTEXT `0x00090014`, RELEASECONTEXT `0x00090018`,
  ISVALIDCONTEXT `0x0009001C`, LISTREADERS(A/W) `0x00090028`/`0x0009002C`,
  GETSTATUSCHANGE(A/W) `0x000900A0`/`0x000900A4`, CONNECT(A/W)
  `0x000900AC`/`0x000900B0`, RECONNECT `0x000900B4`, DISCONNECT `0x000900B8`,
  BEGIN/END TRANSACTION `0x000900BC`/`0x000900C0`, STATUS(A/W)
  `0x000900C8`/`0x000900CC`, TRANSMIT `0x000900D0`, CONTROL `0x000900D4`,
  GETATTRIB `0x000900D8`, CANCEL `0x000900A8`, ACCESSSTARTEDEVENT `0x000900E0`.
- Length range constraints that a hardened parser should enforce (IDL
  `[range(...)]`): `Transmit_Return.cbRecvLength` **`range(0, 66560)`**;
  `ListReaders_Return.cBytes` `range(0, 65536)`; ATR is 36 bytes;
  reader/context handles are ≤16 bytes in this implementation.

Key implementation focus:

- MS-RDPBCGR is the authoritative protocol family for RDP connection sequencing.
- BAF/RDSAAD work needs the pre-MCS ordering, RDSAAD protocol negotiation,
  Server Nonce, Authentication Request, and Authentication Result semantics.
- `S_OK` is meaningful only after XRDP has completed full BAF authorization and
  session-ready state creation.
- Microsoft documentation is not mirrored here by default. Use the fetch script
  only if local license review permits offline copies.
