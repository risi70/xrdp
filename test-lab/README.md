# Phase 6 KVM Integration Lab

This directory contains the Phase 6 KVM/libvirt integration lab for the XRDP
Broker Authentication Framework (BAF). It uses KVM/libvirt only; Docker is not
part of this phase.

The lab target is a two-VM setup with `xfreerdp` running on the host:

```text
host
  - xfreerdp client
  - libvirt/KVM
  - Ansible control
  - test runner

VM openuds-broker
  - OpenUDS-compatible broker environment
  - BAF reference broker/issuer
  - signing key and broker policy managed as lab-only local state

VM ubuntu-vdi-01
  - Ubuntu 24.04
  - XRDP built from this source tree with --enable-broker-auth --disable-rfxcodec
  - BAF trusted runtime config
  - replay service
  - NSS/PAM test identity
```

Phase 6 does not add OpenUDS-specific logic to XRDP core. The OpenUDS-facing
pieces are lab adapter and broker-reference artifacts only.

## Quick Start

1. Install host prerequisites: `libvirt-daemon-system`, `qemu-kvm`,
   `cloud-image-utils`, `ansible`, `openssh-client`, and a package that provides
   `xfreerdp`.
2. Place an Ubuntu 24.04 cloud image at
   `test-lab/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img`, or set
   `UBUNTU_CLOUD_IMAGE=/absolute/path/to/image.img`.
3. Provide an SSH public key using `LAB_SSH_PUBKEY=/path/to/id.pub`, or use the
   default `~/.ssh/id_ed25519.pub` / `~/.ssh/id_rsa.pub` if present.
4. Create the network and VMs with `test-lab/kvm/scripts/`.
5. Run Ansible with `test-lab/kvm/ansible/playbooks/site.yml`.
6. Run `test-lab/kvm/scripts/run-phase6-tests.sh`.

Large images, ISO files, generated disk overlays, reports, logs, sockets, and
private keys must remain untracked.

## Provisioning Flow

Use the helper scripts in this order for a full local lab:

```bash
cd test-lab/kvm
scripts/check-prereqs.sh
scripts/check-image.sh
scripts/create-lab.sh
scripts/run-phase6-tests.sh --require-vms
```

For CI or a host without provisioned VMs, use:

```bash
test-lab/kvm/scripts/run-phase6-tests.sh --static-only
```

## Image Download Helper

Image downloads are explicit opt-in. To place the Ubuntu 24.04 cloud image at
the default lab path, run:

```bash
test-lab/kvm/scripts/download-ubuntu-image.sh
```

Provisioning scripts never download large images implicitly.
