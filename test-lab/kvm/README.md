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
