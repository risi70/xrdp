# Phase 4: Linux identity binding and PAM checks

Phase 4 separates signed broker claims from the local Linux identity. A
validated capability supplies only `preferred_username`. `baf_identity_bind()`
validates that name and resolves it through the system NSS interface using
`getpwnam_r()` and reverse `getpwuid_r()` canonicalization. Consequently local
files, SSSD, LDAP, FreeIPA, and Active Directory participate only through the
administrator's `nsswitch.conf`; XRDP calls no directory-specific API.

The resolved object owns the canonical username, UID, primary GID, home, shell,
and NSS result. Empty, overlong, control/whitespace-containing, or slash-bearing
names are rejected. Domain forms such as `DOMAIN\\user` and `user@domain` are
permitted syntactically but succeed only when NSS resolves them. UID 0 is
rejected by default. Assertion groups and roles are not treated as Unix groups.

`baf_identity_bind_and_authorize()` accepts only an opaque validator result.
After binding it calls `auth_prevalidated_broker()`. On PAM builds this reuses
the existing PAM common path with authentication disabled: `pam_start()` and
`pam_acct_mgmt()` remain mandatory, while only `pam_authenticate()` is skipped.
The returned existing `auth_info` handle retains the standard
`auth_start_session()` (`pam_setcred()` and `pam_open_session()`) and
`auth_end()` (`pam_close_session()`, credential deletion, and `pam_end()`)
lifecycle. Non-PAM authentication builds fail this entry closed.

Replay reservations are not released by identity or PAM failures. Once the
validator produced the capability, another validation of the same assertion
returns replay until expiry.

Live broker session startup remains deliberately disabled. Phase 3 left the
SCP/EICP codecs disconnected from the production state machine and documented
the 8 KiB libipm limit versus the validator's 16 KiB default. This phase
produces an identity-bound, PAM-account-approved handle only; connecting that
handle to a successful broker login response and existing session lifecycle
requires resolving that transport limit and completing production state-machine
wiring. Classic password login is unchanged.

Run focused tests with:

```sh
./configure --disable-rfxcodec --enable-broker-auth
make -j2
make -C tests/baf check
python3 tests/baf/test_pam_broker_contract.py
python3 tests/baf/test_security_contract.py
```

The identity test uses both a real local NSS lookup and deterministic resolver
fixtures for success, missing/ambiguous users, UID 0, unsafe names, domain name
syntax, capability enforcement, and replay after later-stage failure. The PAM
contract test verifies the production call graph without weakening production
PAM code or requiring host-specific PAM policy in normal unit tests.
