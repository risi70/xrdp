# Microsoft Notes

Key implementation focus:

- MS-RDPBCGR is the authoritative protocol family for RDP connection sequencing.
- BAF/RDSAAD work needs the pre-MCS ordering, RDSAAD protocol negotiation,
  Server Nonce, Authentication Request, and Authentication Result semantics.
- `S_OK` is meaningful only after XRDP has completed full BAF authorization and
  session-ready state creation.
- Microsoft documentation is not mirrored here by default. Use the fetch script
  only if local license review permits offline copies.
