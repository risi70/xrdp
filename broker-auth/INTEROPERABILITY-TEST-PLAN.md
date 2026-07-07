# Phase 5 Interoperability Test Plan

## Mode A - Native RDSAAD Client

Test clients:

- IGEL OS / RD Core client;
- FreeRDP 3.x patched or configured test client;
- any compatible RDSAAD-capable RDP client.

Required observations:

- RDSAAD negotiation is observed;
- Authentication Request is observed;
- `rdp_assertion` is present;
- XRDP BAF validation succeeds for a valid assertion;
- XRDP BAF validation fails for invalid assertions;
- Ubuntu session starts as the NSS-resolved Linux user;
- smartcard redirection into the Ubuntu session is tested separately for
  application use.

Mode A must be proven with actual client interoperability. Public IGEL / RD
Core documentation does not currently prove arbitrary custom assertion
injection for every deployment.

## Mode B - Broker Gateway RDSAAD

Required flow:

```text
IGEL standard RDP client
-> gateway
-> gateway performs RDSAAD to XRDP
-> XRDP validates BAF assertion
-> Ubuntu session starts
```

Tests:

- IGEL standard RDP client connects to gateway without custom plugins;
- gateway performs RDSAAD to XRDP;
- XRDP validates BAF assertion;
- Ubuntu session starts as the resolved Linux user;
- smartcard redirection model is documented separately from broker SSO;
- gateway fails closed on missing authorization, RDSAAD failure, and XRDP
  Authentication Result failure.

## Negative Tests

Both modes must cover:

- bad signature;
- wrong audience;
- wrong target;
- expired assertion;
- replay;
- unknown user;
- UID 0;
- PAM denial;
- gateway unavailable for Mode B;
- replay service unavailable.

Normal CI uses deterministic reference broker and gateway contract tests.
External client, IGEL, FreeRDP, and UDS server tests belong in the Phase 6 lab
or release interoperability environment.
