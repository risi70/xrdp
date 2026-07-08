# KVM/libvirt Lab

This lab provisions `openuds-broker` and `ubuntu-vdi-01` with libvirt/KVM. It
assumes a Linux host with hardware virtualization enabled and access to the
system libvirt daemon.

## Host Tools

Required commands:

- `virsh`
- `qemu-system-x86_64`
- `cloud-localds`
- `qemu-img`
- `ansible-playbook`
- `ssh`
- `xfreerdp`

The scripts fail early with a clear error if a required tool is missing.

## Images

Use an Ubuntu 24.04 cloud image. Either set:

```bash
export UBUNTU_CLOUD_IMAGE=/path/to/ubuntu-24.04-server-cloudimg-amd64.img
```

or place it at:

```text
test-lab/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img
```

The lab never downloads large VM images automatically.

## Network

The default lab network is `xrdp-baf-lab` on `192.168.126.0/24`.

- `openuds-broker`: `192.168.126.10`
- `ubuntu-vdi-01`: `192.168.126.20`

## OpenUDS Status

The current lab includes an OpenUDS-compatible reference mode. It models
OpenUDS-like user/session/resource objects and routes them through the
broker-neutral BAF reference broker. A real OpenUDS deployment can replace this
adapter without XRDP core changes.

## Operational Helpers

Run `scripts/check-prereqs.sh` before provisioning. It verifies required host
commands, `/dev/kvm`, libvirt daemon state, SSH key availability, and the Ubuntu
cloud image path.

Run `scripts/check-image.sh` to inspect the configured Ubuntu cloud image without
downloading anything.

Run `scripts/create-lab.sh` for the normal lab sequence: prerequisite check,
network creation, VM creation, SSH wait, source synchronization to
`ubuntu-vdi-01:/opt/xrdp-src`, and the Ansible site playbook.

Run `scripts/sync-source.sh [target] [destination]` to refresh the source tree on
the VDI VM. The sync excludes `.git`, build products, VM images, artifacts,
reports, and Python caches.

`run-phase6-tests.sh` supports two important modes:

```bash
./run-phase6-tests.sh --static-only
./run-phase6-tests.sh --require-vms
```

`--static-only` runs syntax/static checks and skips all VM-dependent checks.
`--require-vms` turns missing libvirt network, missing domains, or unreachable
VMs into hard failures.

## Optional Image Download Helper

The lab does not download VM images automatically during provisioning. If you
want the helper to fetch the Ubuntu 24.04 cloud image explicitly, run:

```bash
test-lab/kvm/scripts/download-ubuntu-image.sh
```

By default it downloads Noble amd64 cloud image data to:

```text
test-lab/kvm/images/ubuntu-24.04-server-cloudimg-amd64.img
```

The script verifies `SHA256SUMS` by default. Override with environment variables
or arguments when needed:

```bash
UBUNTU_CLOUD_IMAGE_URL=https://example/image.img UBUNTU_CLOUD_IMAGE=/absolute/path/image.img test-lab/kvm/scripts/download-ubuntu-image.sh --force
```

Downloaded images remain ignored by git.
