# IGEL and Standard RDP Broker Flow

Phase 5 keeps the endpoint as a standard RDP client. No custom IGEL client,
IGEL helper, FreeRDP plugin, dynamic virtual channel, or endpoint-side BAF
helper is required by the XRDP BAF path.

## Intended User Flow

```text
user authenticates on IGEL and/or presents smartcard
-> broker authenticates user and offers sessions
-> user selects Ubuntu VDI target
-> broker issues target-bound BAF assertion
-> RDP/RDSAAD carries rdp_assertion
-> XRDP validates BAF assertion
-> trusted replay service reserves single use
-> NSS/SSSD resolves Linux user
-> PAM account/session preconditions pass
-> Ubuntu session opens as resolved Linux user
```

The BAF assertion is carried by the RDSAAD-style pre-logon assertion exchange,
not by username or password fields.

## Smartcard Scope

Broker SSO and smartcard redirection are separate concerns:

- broker SSO avoids password re-entry into Ubuntu;
- smartcard authentication may be part of broker-side authentication context;
- application-level smartcard use inside the Ubuntu session still requires
  normal RDP smartcard redirection;
- smartcard redirection does not replace XRDP's BAF validation, trusted replay,
  NSS/SSSD identity binding, or PAM account/session lifecycle.

## Broker Neutrality

UDS Enterprise can be a broker implementation, but XRDP core remains generic.
UDS, Keycloak, Entra, or other provider-specific behavior belongs in external
broker adapters or deployment policy, not in `libxrdp`, `xrdp`, `sesman`,
`sesexec`, `libipm`, the BAF validator, or the RDSAAD parser.
