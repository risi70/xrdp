# IGEL Notes

Key implementation focus:

- IGEL OS 12 must remain a standard RDP endpoint for the MVP path.
- Smartcard redirection is separate from broker SSO and may still be needed for
  in-session application authentication.
- If IGEL/RD Core cannot inject arbitrary `rdp_assertion`, use Mode B broker
  gateway RDSAAD rather than endpoint customization.
