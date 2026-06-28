# GoodBehavior — TODO

Open work on the bundle itself. Keep everything here **generic** — GoodBehavior is a portable method, not a record of any
one project. Project-specific instances are where these lessons are *learned*; this file is where the **generic** form
gets baked back into the loop.

## The mechanism this file serves: local learnings → baked into the loop

GoodBehavior should improve by **promoting locally-learned good practices into its generic principles.** A project hits a
trap, `/learn-goodbehavior` records it as a project memory, and when that lesson is really a *general* discipline (not a
project fact), its generic form is distilled into `CLAUDE.md` / the relevant skill — so every future adoption inherits it.
The self-update model (`/update-goodbehavior`, 3-way merge) is the carrier: a principle improved in one project's copy can
flow upstream and back out to others.

- [ ] **Build the promotion path.** Extend `/learn-goodbehavior` (or add a step) to distinguish a *project fact* (stays
      in project memory) from a *general discipline* (gets a generic rewrite proposed into `CLAUDE.md`/a skill). Ask
      before editing principles; never auto-rewrite the persona.
- [ ] Decide how a project-local principle improvement travels back to the source repo (PR? a "contribute-up" note in
      `/update`?), so good practice isn't trapped in one copy.

## Promoted into the loop (log)

- **2026-06-28 — four promotions distilled from an adopter survey** (a real project running the bundle; identity stripped,
  generic form only). (1) **Standing-proceed** — an earned escalation of trust: once the user has seen the gates hold,
  the loop may run a plan unattended, pausing only for a genuine design decision / real failure / irreversible step; it
  removes the pause *between* items, never a guardrail. Baked into `CLAUDE.md` (new "Standing-proceed" section + "Don't
  sidetrack") and `gate-build-`. (2) **Verified-vs-unverified labeling** — tag claims/findings `✔` firsthand vs `⚠`
  relayed; never let a `⚠` drive a build; re-read load-bearing state. Baked into `CLAUDE.md` "Honesty under pressure" +
  `audit-`/`gate-build-`. (3) **Adversarial, multi-lens audit** — run independent lenses (security / coverage-vs-journeys
  / completeness-wiring / flow-UX / coherence) and surface contradictions; into `audit-`. (4) **UAT plan** — a living
  manual user-test map (feature set → how to test → pass/fail close-out); new `/uatplan-goodbehavior` skill +
  `templates/UAT-PLAN.md`, wired into `verify-`/`gate-build-`/`audit-`.
- **2026-06-23 — adopt: separate run-locally from deploy-trigger and verify-target.** Surfaced while adopting a real
  push-to-deploy project (a managed host watching a branch + a managed backend): adopt had recorded the *local* run
  commands as "the dev approach" and missed that deploy was push-to-branch (host + CI auto-deploy) and that **verify runs
  against the deployed URL, not localhost** — and that a build-only pipeline catches no logic bugs. Baked generically into
  `/adopt-goodbehavior` Phase 1 (probe deploy/hosting config; analyze three facets) + Phase 2 (confirm the three facets
  separately; flag push=deploy; capture the verify URL).

## Coverage gap: "report verified state, not intentions" (generic)

The bundle covers *basic* honesty (claim only what you can show; observe real behavior, not a green test; confirm you're
on the current build; don't carry an unverified item forward). The sharper sub-points below were **promoted 2026-06-28**
into `CLAUDE.md` "Honesty under pressure" + "Standing-proceed" and reinforced in `audit-`/`gate-build-`/`verify-` (see the
promotion log above):

- [x] **Relayed findings are claims, not facts.** A result from a sub-agent, an audit, a search, or a prior summary is
      *to-verify*, not established truth — don't act on it as fact until observed firsthand. *(→ Honesty under pressure +
      `audit-` ✔/⚠ tags.)*
- [x] **Re-read load-bearing facts; don't trust recollection.** State that drives a decision — file contents (especially
      after edits), versions, identifiers, environment/build state — must be re-read from source, not recalled. *Why:*
      long sessions and context compaction summarize away the raw observations; durable docs preserve **decisions, not
      current state**, so current state is recovered by re-reading, not remembering. *(→ Honesty under pressure.)*
- [x] **Name the cost, so the discipline lands.** The expensive waste isn't a long session — it's the span between a
      hollow "done/verified" and the moment the gap surfaces, plus the rework to unwind everything built on it. *(→
      Honesty under pressure, stated as the rationale.)*
- [x] **Verified-vs-unverified labeling as the core move.** Explicitly mark unverified work as unverified; "wrote/changed
      it" is a different claim from "ran it and observed the result." *(→ Honesty under pressure + the `✔`/`⚠` convention
      across `audit-`/`gate-build-`.)*
- [x] **Length is not itself a reason to hesitate or checkpoint.** With recovery docs + re-verify discipline in place, a
      long run is fine — keep executing; don't stop-the-world or ask "should I continue?" as a reflex. *(→ "Standing-
      proceed" in `CLAUDE.md` + `gate-build-`.)*

## Carried-over open items (install/update thread, done 2026-06-23 — these remain)

- [ ] **Initial commit of the source repo.** `/update-goodbehavior` needs a real merge base; until the GoodBehavior repo
      is committed, `sourceCommit` is `null` and update can't 3-way-merge. (Don't commit without the user's go-ahead.)
- [ ] **Exercise the round-trip.** Prove `/adopt` → make a local tweak → `/update` actually merges (untouched files
      fast-forward, adapted files merge, conflicts mark) against a second commit. Currently unproven.
- [ ] **Trial on a real existing project** (e.g. an adopt run somewhere with its own stack/conventions) to surface gaps by
      use, not inspection.
