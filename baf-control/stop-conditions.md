# Stop Conditions

Stop and report instead of continuing if any of these conditions occur.

## Architecture and protocol

- A safe RDSAAD insertion point cannot be identified.
- `S_OK` would need to be emitted before full authorization.
- Live activation would require username/password assertion overloading.
- Live activation would require a custom IGEL client, FreeRDP plugin, dynamic virtual channel, or endpoint helper.
- XRDP/libxrdp cannot safely bridge RDSAAD assertion authorization into xrdp/sesman/sesexec.
- MS-RDPBCGR wire structures are ambiguous or cannot be implemented safely.
- A design assumes that a stock AAD/Entra client can carry a broker-neutral BAF assertion.
- Work would silently select SD-008 or proposed SD-009 before the ingress decision is resolved.

## Security

- Raw assertions would need to be logged or persisted beyond the required validation path.
- Trusted replay service cannot be used for live activation.
- Process-local replay would be required for live activation.
- Token-derived UID/GID or Unix groups would need to be trusted.
- `trusted=true` or equivalent bypass would be required.

## Identity and PAM

- System NSS identity binding cannot be separated from assertion validation.
- PAM account/session cannot be enforced without changing classic login behavior.
- Broker-auth would need to call `pam_authenticate()`.
- Classic PAM/password login behavior would change.

## Scope

- XRDP core implementation would require UDS-specific, Keycloak-specific, or Microsoft identity assumptions.
- BAF release, interoperability, or lab acceptance would require LDAP provisioning/synchronization, SSSD configuration/availability, Active Directory, Kerberos, domain join, or Microsoft Entra.
- Phase 5 interoperability work would need to be mixed into generic Phase 4 work.
- Tests cannot prove the security boundary being modified.
