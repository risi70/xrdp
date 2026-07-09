# External Reference Catalog

This directory catalogs external documentation relevant to BAF/RDSAAD, UDS
Enterprise, IGEL OS 12, Ubuntu 24.04 VDI targets, FreeRDP, KVM/libvirt, and
Ansible.

It intentionally does **not** commit full third-party documentation copies by
default. Many vendor documents are copyrighted or governed by click-through or
website terms. Instead, this tree stores:

- supplier-specific indexes;
- stable source URLs where known;
- short implementation notes;
- a manifest for operator-controlled retrieval;
- ignored `originals/` and `converted/` folders for locally authorized offline
  copies.

To fetch documents for offline use, run:

```bash
python3 docs/references/fetch_references.py --accept-third-party-licenses
```

Only run the fetcher if your organization is allowed to store local copies of
the referenced documents. Downloaded files are ignored by git.

GitHub cannot make one directory private inside a public repository. To commit
and push offline copies, use a separate private Git checkout under
`docs/references/private/`; see `PRIVATE-REPO.md`.

## Supplier Layout

- `microsoft/` - RDP open specifications, RDSAAD, AVD/RDP properties.
- `igel/` - IGEL OS 12 and UMS endpoint configuration.
- `virtual-cable/` - UDS Enterprise broker documentation.
- `freerdp/` - FreeRDP client and implementation references.
- `ubuntu/` - Ubuntu 24.04 target OS, cloud images, PAM/SSSD.
- `libvirt/` - KVM/libvirt lab runtime.
- `ansible/` - Ansible provisioning.
- `neutrinolabs/` - XRDP/xorgxrdp upstream.
- `openuds/` - OpenUDS community/upstream material.
