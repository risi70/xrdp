# CI/CD Strategy

## 1. Requirements

| ID | Requirement |
|---|---|
| CICD-001 | Every change MUST build and test classic and broker-enabled modes. |
| CICD-002 | No generated artifact is published unless sourced from a reviewed, signed tag. |
| CICD-003 | Dependencies and images MUST be pinned, inventoried, and scanned. |
| CICD-004 | Privileged tests MUST not run with secrets for untrusted contributions. |
| CICD-005 | Upstream XRDP compatibility MUST be continuously tested. |

## 2. Branch and review model

- `devel` tracks the supported upstream XRDP base and remains releasable.
- Feature branches are short-lived; `baf/*` is a naming convention, not a
  long-lived integration fork.
- Pull requests require two approvals, including security-owner approval for
  trust, protocol, PAM, configuration, or cryptography changes.
- CODEOWNERS protects BAF validator, protocol, and security specification.
- Linear history or reviewed merge commits are permitted; force-push to
  protected branches is prohibited.
- A scheduled bot opens upstream-rebase PRs and runs the complete matrix.

## 3. Release model

Semantic versions apply to BAF profile and packaging independently of XRDP.
Release branches are `release/1.x`; tags are signed `baf-v1.x.y`. Protocol/profile
major changes require migration documentation. Security fixes may be backported
to the supported minor series. Reproducible source tarballs, Ubuntu packages,
SBOMs, provenance, checksums, and documentation are published together.

## 4. Pipeline

1. **Format/lint:** XRDP style, Python Ruff/Black checks, Markdownlint,
   JSON Schema validation, Mermaid rendering.
2. **Build matrix:** GCC/Clang; broker off/on; PAM; Ubuntu 24.04; debug/release.
3. **Unit/conformance:** Check/CMocka, pytest, static vectors, replay races.
4. **Static analysis:** compiler `-Werror`, clang-tidy, cppcheck, CodeQL,
   Python type/lint analysis.
5. **Security:** dependency review, OSV/Dependabot, secret scan, Semgrep,
   container/package scan, SBOM.
6. **Sanitizers/fuzz:** ASan/UBSan per PR; TSan, fuzz corpus, Valgrind nightly.
7. **Integration:** Docker services and NSS/PAM tests on trusted runners.
8. **System:** KVM smoke nightly; full security/stress on release candidate.
9. **Package/install/upgrade:** build DEB, install, restart, classic rollback,
   configuration migration.
10. **Publish:** signed provenance and artifacts only from protected tag.

## 5. Coding and documentation standards

C follows upstream XRDP style and ownership/error conventions. Python targets
the Ubuntu 24.04 supported version, uses type hints, and has no runtime role in
XRDP. Public interfaces and security decisions require documentation and tests.
Warnings are errors. New custom crypto, JWT parsing, networking, or identity
resolution requires architecture review demonstrating why mature software
cannot be reused.

Specifications are versioned alongside code. CI validates links, requirement
IDs, duplicate IDs, JSON examples, schema examples, and Mermaid syntax.
Generated HTML/PDF is published from the same tag.

## 6. Supply-chain controls

- Generate SPDX or CycloneDX SBOM for source, DEB, container, and Python tools.
- Pin GitHub Actions by commit and containers by digest.
- Verify source archive and Ubuntu package signatures.
- Use isolated, ephemeral signing with OIDC-backed provenance; no long-lived
  signing key in CI.
- Apply SLSA-compatible provenance and reproducible-build comparison.
- Block critical/high exploitable findings unless security owner documents
  time-bounded acceptance.

## 7. Artifacts and retention

PR artifacts: JUnit, coverage, sanitizer logs, rendered specifications, and
packages retained 14 days. Nightly KVM artifacts retained 30 days. Release
artifacts and SBOM/provenance are permanent. Logs undergo secret scanning and
redaction before upload; pcaps containing assertions are encrypted and
restricted or discarded.

## 8. Merge and release gates

Merge requires green mandatory jobs, requirement/test traceability, no diff
warnings, and review. Release additionally requires system acceptance,
24-hour stress, key rotation/recovery drill, threat-model sign-off, upgrade and
rollback, documentation approval, zero secret findings, and signed artifacts.

## 9. Upstream strategy

Keep patches small and separable: protocol primitives, provider interface, PAM
prevalidated path, validator, tests, then documentation. Avoid reference-broker
code in upstream XRDP. Track upstream weekly, rebase feature work, and submit
general-purpose patches with classic behavior demonstrated by tests.
