---
name: audit-goodbehavior
description: Produce an honest, reference-cross-checked gap register — the concrete delta between what exists and what's wanted, grouped and severity-tagged, built in gated batches (not all at once). Use before building, when the user wants to know "what are ALL the gaps" against a reference (design, spec, competitor, demo).
---

Catalog the gaps between the current build and the reference, concretely and honestly. The output is a gap register
under `docs/audit/`, which `/roadmap-goodbehavior` later rolls into a plan.

## Non-negotiables
- **Grounded in the real thing.** Every claim cites the actual file/screen/endpoint you just looked at — not memory.
- **Cross-checked against the reference**, element by element. The gap is the *delta* (what the reference has that we
  don't, or differs), stated concretely — not paraphrased ("looks different").
- **Gated batches.** Pick a grouping (by journey / feature area / page) and do **one batch per pass**, reviewed before
  the next. Don't dump a shallow everything-at-once list.
- **No false "covered."** If you didn't check it, say so. Severity-tag each gap (P0 breaks parity / P1 / P2 polish).
- **Tag each finding verified or relayed.** `✔` = confirmed against the real code/screen/endpoint you just read; `⚠` =
  relayed/inferred (from a sub-agent, a prior summary, a quick grep) and still to confirm. A `⚠` finding is a lead, not a
  fact — never roll it into the roadmap as settled without confirming it firsthand.

## Adversarial, multi-lens
A single read only finds what it was looking for. Pass each area through **independent lenses** and surface where they
*contradict*, not just what each turns up. At minimum: **security**, **coverage vs the intended journeys/spec**, and
**completeness/wiring** (is it actually reachable end to end, or a dead surface?); add **flow/UX** and **internal
coherence** for user-facing areas. Run the lenses as separate passes — or parallel sub-agents, each blind to the others —
then reconcile. A contradiction between two lenses (one says "done," another "unreachable") is itself a P0/P1 finding.

## Per-batch template (one file per batch, e.g. `docs/audit/01-<area>.md`)
1. **Reference** — what the target shows/does for this area (with the source: screenshot, spec section, URL).
2. **Ours today** — what we render/do now (cite the real code/screen).
3. **Reuse check** — existing framework/library/components that fit but we hand-rolled or skipped.
4. **Flow** — the click/call path; where it breaks or is missing.
5. **Backend/data/security** — what backs it; scoping/access; data quality.
6. **Gaps** — the concrete deltas, each with P0/P1/P2 **and a `✔`/`⚠` verification tag** (confirmed firsthand vs still
   to confirm).

Keep an index (`docs/audit/00-index.md`) with batch status and the enumerated real surface (the actual list of
screens/endpoints/components), so coverage is auditable.

## Finish
Roll the per-batch gaps up into `docs/plans/ROADMAP.md` via `/roadmap-goodbehavior`. The audit *documents* gaps — it does not build
them; don't start fixing mid-audit.
