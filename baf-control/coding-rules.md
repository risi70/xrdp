# BAF Coding Rules

- Prefer small, reviewable patches.
- Keep BAF code behind `--enable-broker-auth` where appropriate.
- Do not expose third-party JWT library types in public XRDP-facing interfaces.
- Keep raw assertion lifetime as short as possible.
- Prefer explicit status enums over booleans.
- Fail closed on unknown status values.
- Preserve classic SYS/UDS/PAM login behavior.
- Add or update tests for every behavior change.
- Update documentation when implementation changes security or phase boundaries.
