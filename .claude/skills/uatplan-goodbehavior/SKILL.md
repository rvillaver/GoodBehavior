---
name: uatplan-goodbehavior
description: Build and maintain a living manual user-acceptance test plan — a map of every feature set, how a human drives each one on the REAL app, the expected result, and a pass/fail checklist to close it out. Complements automated tests and feeds /verify-goodbehavior. Use to make verification coverage durable and auditable, not ad hoc.
---

Produce and keep current a **human-followable UAT plan** — the durable counterpart to automated tests and to the one-shot
`/verify-goodbehavior` drive. Where verify proves *one* change live, the UAT plan is the *standing map* of what to test
across the whole product and whether each case currently passes. Output: `docs/qa/UAT-PLAN.md`, kept in sync with the
feature set as it grows (start from `templates/UAT-PLAN.md`).

## Organize by feature set (cross-referenced to journeys/personas)
Enumerate the **real, as-built feature set** from the code/screens — not from memory or the design doc alone — grouped
into areas (identity, each operator surface, the core loop, public/landing, …). If the project has persona/journey docs,
cross-reference them so coverage is auditable against the *intended* journeys. Where roles exist, include a **permutation
matrix** (role × page/action: who can do what, and what the blocked case looks like).

## Per case
A stable **case ID** (e.g. `TC-<area><n>`), and for each:
1. **Steps** — the exact user actions, end to end, on the real app (navigate, fill, submit).
2. **Expected** — the observable result to compare against: UI state *and* the backend effect (row written, count moved,
   state advanced). UI-only expectations miss half the bugs.
3. **Result** — `[ ] Pass [ ] Fail` + notes, filled when the case is actually driven.

Flag **known/expected gaps** explicitly (blocked-on-X, by-design-absent) so a fail there isn't misread as a regression.

## Keep it live
- It is **ongoing, not one-shot.** When a feature ships, add or adjust its cases in the *same* change; when a behavior is
  ratified as by-design, record it. Supersede stale cases explicitly (keep the history) rather than silently deleting —
  so a once-passing case can't quietly mislead.
- Mark each case honestly: `Pass` only with firsthand live evidence (`✔`), never a relayed/assumed result (`⚠`). The
  whole value of the plan is that its green is *trustworthy*.

## How it wires into the loop
- `/gate-build-goodbehavior` closes a phase by driving that phase's UAT cases through `/verify-goodbehavior` — a phase
  isn't done until its cases pass live, user-confirmed.
- `/audit-goodbehavior` coverage is checked against this plan: a real feature with **no UAT case** is itself a coverage gap.
- Put a short **reporting protocol** at the foot (case ID, role, page/URL, steps, saw-vs-expected, time, screenshot) so
  human testers log issues consistently and patterns are visible.

## Anti-patterns
- A green automated suite is **not** a passed UAT plan — this is the human / real-app layer that catches what unit tests
  can't. Necessary, not sufficient.
- Enumerating from memory or the design doc instead of the **as-built** surface (cite the real screens/endpoints).
- A plan that rots: cases not updated when the feature changed, so its green no longer means anything.
