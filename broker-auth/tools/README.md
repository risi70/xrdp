# Broker integration tools

`baf_handle_client.py` is a broker-neutral Python client for registering an
assertion with the local Broker-RDP Handle service. It implements the same
bounded `SOCK_SEQPACKET` protocol as
`sesman/libsesman/baf_handle_service.c`.

The service socket must be exposed only across a trusted broker-to-VDI path.
The tool does not validate assertions or replace XRDP authorization.
