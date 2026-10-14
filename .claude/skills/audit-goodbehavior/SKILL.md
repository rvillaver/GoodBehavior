---
name: audit-goodbehavior
description: Produce a gap register — the concrete delta between what exists and what's wanted, cross-checked against a reference. Use when the user wants to know "what are ALL the gaps" against a design, spec, competitor, or demo.
---

**Loop position:** step 2 — after *Understand*, before `/roadmap-goodbehavior`. The doctrine (loop, done rule, lenses) is
the project's active profile (`.claude/goodbehavior/profiles/`), already in your instructions — don't restate it, apply it.

**Nothing built yet?** If the workspace has no code to compare against the reference, the audit is one line — "0% built;
reference = <doc>" — and the next step is `/roadmap-goodbehavior` from the reference's own sections. Don't hunt for a
build elsewhere on the machine and don't interrogate the user.

Catalog the gaps between the current build and the reference, concretely and honestly. The output is a gap register
under `docs/audit/` (a **default, not a prescription** — if the project keeps findings elsewhere per its recorded
conventions, write there), which `/roadmap-goodbehavior` later rolls into a plan.

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
*contradict*, not just what each turns up. Use the lenses listed in the active **profile** — the development set below is
one instance. At minimum: **coverage vs the intended reference/spec** and **completeness/wiring** (is it actually
reachable/usable end to end, or a dead surface?); for software add **security** and **flow/UX**; for analysis add
**data correctness/lineage**; for research add **source provenance**; for creative add **factual integrity & internal
coherence**; for devops use the profile's lenses, which include **cost** (over/under-provisioning, redundancy, pricing) and **code**, and run its "Audit coverage" checklist batches (security, cost, code: one row per guide rule, plus the scanners). Run the lenses as separate passes — or parallel sub-agents, each blind to the others —
then reconcile. A contradiction between two lenses (one says "done," another "unreachable") is itself a P0/P1 finding.

## Per-batch template (one file per batch, e.g. `docs/audit/01-<area>.md`)
1. **Reference** — what the target shows/does for this area (with the source: screenshot, spec section, URL).
2. **Ours today** — what we render/do now (cite the real code/screen).
3. **Reuse check** — existing framework/library/components that fit but we hand-rolled or skipped.
4. **Flow** — the path a consumer takes through it (per the profile: click/call path; data run-to-output; claim→source
   trail; the narrative/reading order); where it breaks or is missing.
5. **What backs it** — per the profile: backend/scoping/access & data quality (software); input data + validation
   (analysis); primary sources (research); the underlying figures/claims (creative).
6. **Gaps** — the concrete deltas, each with P0/P1/P2 **and a `✔`/`⚠` verification tag** (confirmed firsthand vs still
   to confirm).

Keep an index (`docs/audit/00-index.md`) with batch status and the enumerated real surface — the actual units for the
profile (screens/endpoints/components; datasets/queries; sources/claims; sections/slides) — so coverage is auditable.
**Carry a status per batch** (open / closed-by-`<plan>`): an index where a settled batch and a live one look identical
tells a reader nothing. When every gap in a batch has shipped, move the batch file to `docs/audit/archive/` and leave
its index line pointing there — the findings stay greppable, they just stop competing for attention with open work.

## Finish
Roll the per-batch gaps up into a plan (`docs/plans/<INITIATIVE>.md`, indexed from `ROADMAP.md`) via
`/roadmap-goodbehavior`. The audit *documents* gaps — it does not build
them; don't start fixing mid-audit.
