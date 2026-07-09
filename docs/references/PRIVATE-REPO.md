# Private Offline Reference Repository

GitHub cannot make a single directory private inside an otherwise visible
repository. For offline third-party reference copies, use a separate private
Git repository checked out under `docs/references/private/`. That directory is
ignored by this repository.

## Setup

Create a private GitHub repository, for example:

```text
github.com:<org>/xrdp-baf-private-references.git
```

Clone it into the ignored checkout path:

```bash
git clone git@github.com:<org>/xrdp-baf-private-references.git docs/references/private
```

Optionally initialize a README in that private repository before the first
fetch/commit.

## Fetch, Commit, and Push

Run the fetcher with an explicit license acknowledgement and point it at the
private checkout:

```bash
python3 docs/references/fetch_references.py \
  --accept-third-party-licenses \
  --output-root docs/references/private \
  --commit \
  --push
```

The script writes supplier-organized files under the private checkout, commits
only successfully fetched files, and pushes that private repository. It refuses
to commit downloaded third-party documents to the main XRDP repository unless
`--allow-main-repo-commit` is supplied. Do not use that override unless the
source license explicitly permits redistribution in this repository.

## Supplier Layout

The private checkout uses the same supplier layout as the public catalog:

```text
docs/references/private/
  microsoft/originals/
  igel/originals/
  virtual-cable/originals/
  freerdp/originals/
  ubuntu/originals/
  libvirt/originals/
  ansible/originals/
  neutrinolabs/originals/
  openuds/originals/
```

## Failure Behavior

If a vendor URL returns `404`, times out, or otherwise fails, the script logs a
warning, continues with the remaining references, and exits nonzero after the
commit/push step. Successfully fetched files are still committed when `--commit`
is used.
