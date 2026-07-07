# BAF Gateway Skeleton

The gateway skeleton documents Mode B: Broker Gateway RDSAAD Mode.

The gateway is outside XRDP core. It receives a broker-authorized session,
obtains or creates a BAF assertion, and performs RDSAAD toward XRDP as a
southbound RDP client. This keeps endpoint clients unchanged and avoids
username/password assertion overloading.

This phase provides documentation, configuration shape, and conformance tests.
It does not implement a production RDP proxy.

Required gateway properties:

- no custom IGEL client requirement;
- no raw assertion logging;
- no username/password assertion overloading;
- no UDS-specific logic in XRDP core;
- fail closed on RDSAAD, replay, identity, PAM, or TLS failure.

The gateway contract requires no username/password assertion overloading and must never log raw assertions. All gateway failures must fail closed.
