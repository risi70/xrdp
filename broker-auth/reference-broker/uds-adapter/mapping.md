# UDS to BAF Mapping Skeleton

The UDS adapter maps UDS-like concepts into broker-neutral BAF assertion
claims. XRDP core does not consume UDS objects.

| UDS concept | BAF concept |
|---|---|
| UDS user ID | `sub` |
| UDS local account mapping | `preferred_username` |
| UDS service/pool | audience or policy context |
| UDS assigned VM | `target` |
| UDS session ID | `broker_session_id` |
| UDS auth method | `auth_method` |
| UDS assurance/policy result | `assurance_level` |

Rules:

- no UDS code in XRDP core;
- no Keycloak-specific code in XRDP core;
- no UDS groups become Unix groups;
- XRDP resolves Linux identity through system NSS;
- UID/GID claims from broker-side data are not trusted by XRDP.
