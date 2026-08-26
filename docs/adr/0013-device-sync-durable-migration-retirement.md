# ADR 0013: Durable Device Sync Migration Retirement

- **Status:** Accepted for evidence-specific registry and PostgreSQL primitives
- **Date:** 2026-08-25
- **Scope:** Final migration authority after the rollback window

## Decision

Migration retirement is not an ordinary route or policy successor. Both the
file-backed BindingRegistry and PostgreSQL require complete
`MigrationRetirementEvidence`, which binds the exact activation evidence to its
immediate authority-signed retirement successor. A bare signed retirement
Manifest is rejected by the generic successor path.

The domain-separated digest of the complete retirement evidence becomes the
terminal transition identity in both durable stores. First application
reconstructs the activation at its historical validity and requires the
retirement Manifest to be live at receipt. An exact applied retry is accepted
before temporal validation.

The deployment roles remain asymmetric:

- The active target stays writable. If it prepared a reverse rollback export,
  retirement validates that exact immutable export as target-to-source under
  the activation authority, clears the active fence, and preserves the export
  record for audit. A target with no reverse export simply advances authority.
- The old source stays retired and non-writable. Its BindingRegistry keeps the
  signed forward fence permanently, while PostgreSQL advances the authority and
  retains immutable export evidence without an active database fence pointer.

Both PostgreSQL paths hold the scope-enforcement row `FOR UPDATE` in a
serializable transaction and atomically update authority, state, and exceptional
fence/import pointers. Unexpected imported state, the wrong migration direction,
changed evidence, or a non-exact activation predecessor fails closed.

## Orchestration boundary

This checkpoint does not yet add a retirement acceptance journal, startup
recovery, route, operator command, or two-host workflow. Those are required
before retirement is production-reachable. The portable fixture and headless
tests prove contract and local transition behavior only. PostgreSQL integration
still requires a disposable `FACETS_SERVER_TEST_DATABASE_URL`; an unset gate is
a skip rather than runtime evidence.
