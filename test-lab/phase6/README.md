# Phase 6 Test Suite

Phase 6 validates the broker-auth architecture in a KVM/libvirt lab. CI-safe
checks are static and boundary checks. Full VM provisioning requires a Linux host
with libvirt/KVM and local Ubuntu 24.04 cloud images.

## Automated Checks

- Shell syntax for lab scripts.
- Ansible syntax for lab playbooks.
- Static checks for expected lab files and security boundaries.
- Optional VM checks if the libvirt lab is running.

## End-to-End Scope

The host runs `xfreerdp` against `ubuntu-vdi-01`. Classic login is tested when
lab credentials are configured. The RDSAAD/BAF assertion path is tested at the
closest supported boundary unless the installed `xfreerdp` can inject arbitrary
`rdp_assertion`. Stock `xfreerdp` is expected to skip that full client-injection
case with an explicit reason.
