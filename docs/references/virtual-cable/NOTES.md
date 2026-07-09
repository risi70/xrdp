# Virtual Cable / UDS Enterprise Notes

Key implementation focus:

- UDS user/session/resource data must be translated by an isolated adapter.
- XRDP core remains broker-neutral; no UDS-specific logic belongs in XRDP core.
- UDS groups and IDs are not Linux Unix groups, UIDs, or GIDs.
- The Ubuntu VDI host resolves Linux identity through NSS/SSSD and enforces PAM.
