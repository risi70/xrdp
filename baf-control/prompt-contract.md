# Prompt Contract for Future Agentic Tasks

Future prompts may be short if they reference this control layer.

A valid task prompt should specify:

1. Phase or acceptance file, for example `baf-control/acceptance/phase-4b-bridge.md`.
2. Any task-specific deviation from the control documents.
3. Whether to commit and push.
4. Whether the task is implementation-only, documentation-only, or both.

Unless explicitly overridden, agents must follow:

- `AGENTS.md`
- `BAF-ARCHITECTURE.md`
- `baf-control/security-invariants.md`
- `baf-control/stop-conditions.md`
- `baf-control/build-and-test.md`
- `baf-control/checklists/preflight.md`
- `baf-control/checklists/final-verification.md`

If a referenced file is missing or contradictory, stop and report.
