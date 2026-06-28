# User-acceptance test plan (manual UAT)

A human-followable map of every feature set, how to drive it on the **real app**, the expected result, and a pass/fail
checklist to close it out. The durable counterpart to automated tests and to a one-shot `/verify-goodbehavior` drive —
maintained via `/uatplan-goodbehavior`. Built from the **as-built** surface (cite real screens/endpoints), kept in sync
as features ship.

- **App / target:** <the deployed URL, or how a human runs it>
- **For each case:** follow the steps, compare to **Expected**, mark `[ ] Pass [ ] Fail`, add notes.
- **A case passes only with firsthand live evidence** (`✔`), never a relayed/assumed result (`⚠`).

## Setup — accounts & preconditions
<test accounts/roles, seed data, how to reach each starting state>

## Real surface (enumerate from the code)
<!-- the actual feature areas / screens / endpoints this plan covers, so coverage is auditable.
     Cross-reference journeys/personas if they exist. -->

## Permutation matrix (if roles/variants exist)
| As… ↓ / Action → | <page A> | <page B> |
|---|---|---|
| <role 1> | ✓ | ✗ (blocked: <what the block looks like>) |
| <role 2> | ✓ | ✓ |

## Cases by area

### A. <area>
**TC-A1 — <title>.** Steps: <the exact user actions>. Expected: <observable UI state **and** backend effect>.
`[ ] Pass [ ] Fail` — notes:

**TC-A2 — <title>.** Steps: <…>. Expected: <…>. `[ ] Pass [ ] Fail` — notes:

### B. <area>
**TC-B1 — <title>.** Steps: <…>. Expected: <…>. `[ ] Pass [ ] Fail` — notes:

## End-to-end run (ties it together)
**TC-Z1.** A full real-world run across roles/screens, in order, confirming the whole loop flows without dead-ends.
`[ ] Pass [ ] Fail` — notes:

## Known / expected gaps
<!-- blocked-on-X or by-design-absent cases, so a fail there isn't read as a regression -->

## Reporting issues
For each failure capture: **case ID** + one-line title · your **role** · **page/URL** · **steps** · **saw vs expected** ·
**time** · screenshot. Group by area so patterns are visible; drop them wherever the team collects issues.
