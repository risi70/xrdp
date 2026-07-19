# Reference UDS Handle Registration Installer

This directory builds a sanitized, reference-only integration artifact for a
trusted broker or OpenUDS transport component. It is deliberately smaller than
a production UDS plugin.

The installed `baf-uds-register` command:

- reads an already issued broker-neutral BAF assertion from a file descriptor;
- registers the assertion with the XRDP trusted Handle service over a Unix
  `SOCK_SEQPACKET` socket;
- prints a single-use Handle, routing-token cookie, or JSON response;
- never accepts a Keycloak token, BAF assertion, password, PIN, or private key
  on its command line.

It does not authenticate users, validate Keycloak tokens, issue BAF
assertions, store an issuer key, implement remote socket protection, or modify
OpenUDS. A production integration must call it only after broker policy has
validated Keycloak and issued the distinct BAF assertion.

## Build and install

```sh
packaging/uds/build-installer.sh
tar -xzf packaging/uds/out/xrdp-baf-uds-reference-*.tar.gz
sudo ./xrdp-baf-uds-reference-*/install.sh
```

## Example

Pass the assertion on an inherited file descriptor or standard input. The
following placeholder names a protected file only to demonstrate descriptor
use; deployments should avoid persistent assertion files:

```sh
baf-uds-register --socket /run/xrdp/baf-handle.sock \
    --target desktop-01 --format cookie 3< /run/broker/assertion.jwt \
    --assertion-fd 3
```

The default maximum TTL is 90 seconds and the accepted range is 1 through 120
seconds. Raw assertions are never written to stdout or stderr.
