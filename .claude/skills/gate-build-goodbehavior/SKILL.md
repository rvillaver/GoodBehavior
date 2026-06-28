---
name: gate-build-goodbehavior
description: Execute one roadmap phase under the gated loop — build each item, verify it live (real app + real flow), record learnings, and prove the phase with concrete evidence before starting the next. Use to work through a roadmap without drifting or self-declaring done.
---

Work the **current (NOW) phase** of `docs/plans/ROADMAP.md`, one item at a time, to the real definition of done.

## Per item
1. **Build** the smallest change that actually closes the gap (reuse before hand-rolling).
2. **Deploy/run** it the project's real way (note the build/deploy traps — see the project's `build-deploy-gotchas`).
3. **Verify live** — run `/verify-goodbehavior`: exercise the real behavior through the real UI *and* backend, like a
   user, and capture evidence (rendered result vs. reference; the flow firing). A passing test alone is **not** verify.
4. **Record learnings** — any non-obvious trap, correction, or build/deploy fact → `/learn-goodbehavior`.
5. **Status** — mark the item done **only with evidence**; otherwise "partial/blocked" + log the blocker to the backlog.

## Gate before the next phase
Loop-review the phase until **every item has concrete evidence** (or is explicitly deferred to the backlog). Record
phase-level learnings. Only then advance. Don't carry an unverified item forward silently. Tag each item `✔` (firsthand
live evidence) or `⚠` (relayed/assumed — **not** done); a phase never advances on a `⚠` item.

## Standing-proceed (when granted)
If the user has granted **standing-proceed** for this plan, run the phases end to end **without per-item check-ins** —
the per-item loop above is unchanged (build → verify live → record → gate), you've just been trusted to run it unattended
against the agreed plan. Keep going; "should I continue?" is not a checkpoint, and length is not a reason to stop. Pause
to ask **only** for: a genuine design decision the plan doesn't settle, a real failure you can't resolve, or a
destructive/irreversible step (a push that deploys, a migration, anything you can't take back). When you pause, say which
of the three it is. Standing-proceed removes the pause between items, never a guardrail — a faked or skipped verify is the
one thing it must never buy.

## Discipline
- **Don't sidetrack.** Hit something off-track? Log it to `PRODUCTION-BACKLOG.md` and keep the throughline.
- **Don't fake or over-claim.** If you can't show it working, it isn't done — say so. Surface real failure output.
- **Don't over-build.** If an item is large + invisible (e.g. a pure refactor with no behavior change), flag it and
  consider the backlog rather than grinding; recommend, let the user decide.
- **Right-size verification to the change**, but never skip the live check on anything user-facing.
