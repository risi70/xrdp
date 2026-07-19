# Final Verification Checklist

Run after changes and tests:

```sh
git status --short
git diff --stat
```

Search and inspect every match:

```sh
grep -R "password.*assertion\|assertion.*password\|FreeRDP\|dynamic virtual channel\|DVC\|custom client\|IGEL helper" -n specification broker-auth xrdp libxrdp sesman libipm tests || true

grep -R "UDS\|Keycloak\|Entra\|Azure AD\|trusted *= *true" -n xrdp libxrdp sesman libipm tests/baf || true

grep -R "log.*assertion\|log.*token\|g_writeln.*assertion\|g_writeln.*token" -n xrdp libxrdp sesman libipm tests/baf || true

grep -R "pam_authenticate\|pam_acct_mgmt\|pam_open_session\|pam_setcred\|getpwnam\|getpwuid" -n libxrdp xrdp sesman/libsesman sesman/sesexec tests/baf || true
```

Acceptable matches must be inspected manually and justified.
