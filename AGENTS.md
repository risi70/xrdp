# Agent Instructions for BAF Development

This repository contains an experimental Broker Authentication Framework (BAF) extension for XRDP.

Agents working on this branch MUST treat the BAF specifications, architecture document, and control files as authoritative unless they contain an implementation-blocking contradiction. If a contradiction is found, stop and report it instead of silently choosing a new architecture.

## Core rules

- Preserve classic XRDP username/password PAM login behavior.
- Broker-auth must remain build-gated and disabled by default.
- Do not use username/password fields to carry broker assertions.
- Do not require a custom IGEL RDP client, IGEL helper, FreeRDP plugin, or dynamic virtual channel for the MVP.
- Do not add UDS-specific, Keycloak-specific, or Entra-specific assumptions to the generic BAF core.
- Do not log raw assertions, raw tokens, or credential-grade assertion material.
- Do not trust UID, GID, home directory, shell, or Unix groups from token claims.
- Linux identity must be resolved through NSS/SSSD-compatible lookup before session startup.
- UID 0 must be rejected by default.
- Broker-auth must not call `pam_authenticate()`.
- Broker-auth must enforce PAM account and required session/credential lifecycle before live session startup.
- Live broker-auth activation must use the trusted replay service; process-local replay is test-only.
- Authentication Result `S_OK` must be emitted only after full authorization and session readiness.
- Fail closed on malformed input, missing config, unavailable replay service, ambiguous state, or incomplete authorization.

## Preferred implementation approach

- Keep changes small and upstream-friendly.
- Reuse existing XRDP, PAM, NSS/SSSD, OpenSSL, libjwt, Jansson, and libipm structures where possible.
- Add explicit data structures for new states instead of overloading existing username/password or SYS/UDS login fields.
- Add tests with every change.
- Keep documentation and implementation aligned.

## Required references

Before implementing BAF-related changes, read:

- `BAF-ARCHITECTURE.md`
- `baf-control/security-invariants.md`
- `baf-control/stop-conditions.md`
- the relevant file under `baf-control/acceptance/`
- current files under `specification/decisions/`
