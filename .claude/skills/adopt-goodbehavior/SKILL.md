---
name: adopt-goodbehavior
description: The intelligent installer & entry point — adopt the GoodBehavior method into a destination project (by path). Elicits the project's intent, resolves its profile (development/analysis/research/creative/devops, composable), analyzes its workflow, proposes tailored amendments WITH OPTIONS, then after confirmation installs via scripts/install.py — integrating with what's already there, never imposing a parallel structure.
---

Bring the disciplined method into a destination project by **adapting to it, not overwriting it**. adopt is the
*intelligent installer*: run it from the GoodBehavior source session and point it at **another project by path**, or run
it inside a project that already has the skills to adopt the current one. Five phases: resolve → **understand intent &
resolve profile** → analyze → propose (ask) → execute. **Change nothing in the target until the user confirms the plan.**

**This method is not dev-only.** It fits development, analysis, research, and creative work alike — the discipline is
invariant; only *what "the real thing / verify / evidence" mean* changes, and that is captured by a **profile**
(`<source>/templates/profiles/`). Never tell the user "GoodBehavior isn't meant for this project." If no profile fits,
elicit the three slots directly (the custom fallback in Phase 1). Ask what the project *is* before sniffing its files.

## Phase 0 — Resolve source & target (no writes)
Establish the two roots before reading anything else, and confirm them back to the user:
- **Source** = the GoodBehavior bundle this skill ships in — the repo/dir that contains `.claude/skills/*-goodbehavior/`,
  `.claude/hooks/done-gate.py`, and `templates/`. Normally the current session's project. Record its absolute path, and
  if it's a git repo its HEAD (`git -C <source> rev-parse HEAD`) — that becomes the merge base for `/update-goodbehavior`.
- **Target** = the destination project to adopt into. Take it from the skill argument (a path). If none was given, ask
  for it. You may use the current project as the target **only if** cwd is itself a real project and is *not* the source
  bundle.
- **Refuse to target the source itself** — don't adopt GoodBehavior into GoodBehavior. If the resolved target equals the
  source, stop and ask for a real destination.
- The target need not be a git repo to install, but note: `/update-goodbehavior` later needs the *source* committed (for
  a merge base), not the target.

## Phase 1 — Understand intent & resolve the profile (ASK FIRST, then corroborate)
Before surveying files, establish **what this project is and what "done" means for it** — this is the step whose
absence made earlier adoptions hyperfocus on dev conventions and balk at non-dev projects. Ask the user (don't infer
the project's *kind* from file types); use `AskUserQuestion` for the load-bearing ones:
- **What is this project, and what does "done / success" look like here?**
- **Who consumes the output, and how would they experience the real thing?**
- **How do you check it's actually right** (not just finished)?

Then resolve the **profile** from `<source>/templates/profiles/`:
1. Read **only `INDEX.md`** first (cheap) — it lists the five cores (development · analysis · research · creative · devops) with
   a `use-when` and truth-source each.
2. Match the user's answers to the **1–2 closest** profiles and **read only those bodies** — never load all five.
3. **Compose slots.** A profile is not a rigid single label; take slots (`the-real-thing` / `verify` / `evidence`) from
   different profiles when the project straddles. Canonical case: a **data pipeline** → build ← `development`, verify ←
   `analysis`, evidence ← `analysis`. State the resolved slots explicitly.
4. **Profile guides.** If a resolved profile has a guide folder next to it (today: `devops/`), its body names the
   guides. Ask which platforms and tools the project uses, then add the always-on guide plus one per platform or tool
   in use, as `<profile>/<guide>` entries in the plan's `profiles` list (e.g. `"devops"`, `"devops/baseline"`, plus
   the platform guide). Read only those guide files. A platform with no guide gets the baseline only; say so in the
   proposal. If the profile ships a guard (`devops/guard.py`), add it as a `profiles` entry too, with `"hook": true`:
   the done-gate hook hands every tool call to it.
5. **Custom fallback — never decline.** If nothing fits, elicit the three slots directly from the user ("what's the real
   thing, how would you check it's right, what counts as proof?") and write a custom profile. adopt must never say the
   method "isn't for this project."

Report the resolved profile + per-slot source as a *proposal* to confirm in Phase 3 — the file survey below only
corroborates it (and gathers stack/workflow specifics); it does not decide the project's kind.

## Phase 2 — Analyze the TARGET (read the repo; corroborate, don't assume the kind)
Survey and report what's actually in the **target project**. This grounds the *specifics* (stack, workflow, existing
docs) — it does **not** override the profile resolved in Phase 1. The dev-workflow facets below apply **when a development
slot is in play**; for a non-dev profile, translate them to that profile's real-thing/verify/evidence (e.g. for
`analysis`, "verify target" = the real input data + the validation you run; for `research`, the primary sources):
- **Stack & platform** — language(s), package manager, framework, services (e.g. Supabase/Deno, Docker, serverless, a
  monorepo with several apps). For non-software projects, the equivalent tooling (notebook/BI stack, doc/deck toolchain).
- **Workflow — separate THREE things; never collapse them.** "How to run it locally" is *not* "how this team ships or
  verifies." Read the deploy/hosting config to ground each (e.g. `Dockerfile`/`compose`, `railway.json`, `vercel.json`,
  `netlify.toml`, `Procfile`, `fly.toml`, `.github/workflows/**`, `Makefile`, host dashboards):
  - **(a) Local dev loop** — how you'd build/run/hot-reload/test on a machine (the fast iteration commands).
  - **(b) Deploy trigger & mechanism** — how a change actually ships: manual command, or push-to-branch auto-deploy
    (which branch? what triggers it — a host watching the repo, a CI workflow, both?), containerized or not.
  - **(c) Verify target** — what "verify live" runs *against*: a **deployed URL** vs localhost; and whether anything in
    CI/the pipeline actually tests behavior (a build-only pipeline catches no logic bugs). Note candidate commands and
    the verify target; don't commit to them yet.
- **Existing context docs** — `CLAUDE.md`, `AGENTS.md`, `HANDOFF.md`, `CONTRIBUTING`, `README`, `docs/`, any
  "read this first" / status / next-steps doc. These are conventions to **integrate with**, not replace.
- **Existing planning & memory** — roadmaps, backlogs, TODOs, issue trackers, ADRs, learnings/notes.
- **Norms** — CI, lint/format, commit/branch conventions, test layout.

## Phase 3 — Propose & ASK (still no execution)
Present a concrete adoption plan grounded in Phases 1 + 2, then ask the user to choose. Use `AskUserQuestion` for the
real decisions; recommend a default for each, and make clear nothing is written to the target until they confirm:
- **Profile & slots (confirm first).** Restate the resolved profile(s) and the per-slot sources from Phase 1 — *the-real-thing
  / verify / evidence* — and let the user correct any slot. This is what makes "done" concrete for their project; get it
  right before anything else.
- **Principles home** — new `CLAUDE.md` · append to an existing CLAUDE.md · or link the principles from the existing
  context doc (e.g. `HANDOFF.md`) so there's no competing source of truth.
- **Dev approach — only when a development slot is in play** (skip for pure analysis/research/creative profiles; confirm
  don't default — and don't conflate run-locally with verify-done). Confirm the three facets
  from Phase 2 *separately*: (a) the local dev/test commands, (b) the **deploy trigger** (push-to-branch auto-deploy —
  a managed host or CI watching the repo, and which branch — vs a manual deploy command; containerized or not), and (c) **what `verify live` runs
  against** — the **deployed URL** or localhost. Show what you found per facet + a recommendation; let the user correct
  any of them. If deploy is push-triggered, flag that **pushing = deploying** (so it needs explicit go-ahead), and if the
  verify target is a deployed URL, capture that URL (ask if it isn't in the repo).
- **Done-gate hook** — install it (project-local) vs off. (Skills and hook are **always project-local copies** — never a
  symlink, never a global `~/.claude/` install — so this is a yes/no, not a scope choice.)
- **Planning** — create `docs/plans/ROADMAP.md` + `PRODUCTION-BACKLOG.md`, or **map onto** an existing roadmap / handoff
  "next steps" / issue tracker.
- **Memory** — project memory dir vs `docs/learnings/`; integrate an existing learnings/notes doc if present.

Install location is **not** a question: everything goes into the **target's** own `.claude/` as a copy, by design (a
project adapts its copy to its stack without touching other projects or your global config; `/update-goodbehavior`
reconciles later via 3-way merge).

## Phase 4 — Execute INTO the target (only after confirmation; idempotent)
Split cleanly: the **mechanics run through `<source>/scripts/install.py`** (identical every time — copy, hash, wire,
manifest); you do only the **judgment steps** the script can't.

1. **Run the installer.** Write the confirmed choices as a plan JSON and execute it:
   ```json
   {
     "source": "<abs source path>", "target": "<abs target path>",
     "skills":   ["audit-goodbehavior", "roadmap-goodbehavior", "gate-build-goodbehavior",
                  "verify-goodbehavior", "uatplan-goodbehavior", "learn-goodbehavior", "update-goodbehavior"],
     "profiles": ["<only the matched profile(s) — never all five>", "<plus matched guides, e.g. devops/baseline>"],
     "hook": true,
     "templates": { "docs/plans/ROADMAP.md": "templates/ROADMAP.md", "...": "per the confirmed planning/memory choices" }
   }
   ```
   ```sh
   python3 <source>/scripts/install.py --plan <plan.json>     # add --dry-run first if unsure
   ```
   The script guarantees: never clobbers (existing files skipped + reported), settings.json merged never overwritten,
   hook made executable, manifest written at `<target>/.claude/goodbehavior/manifest.json` with sourceCommit + a sha256
   per file as installed (warns if the source has no commits — update can't 3-way-merge until it does). Re-runs are
   no-ops. **Note `adopt-goodbehavior` itself is NOT shipped** — it's a run-once installer; post-install the target only
   needs the working skills plus `/update-goodbehavior`. Relay the script's created/skipped/warnings report.
2. **Principles** (judgment): merge into the chosen home in the target (the core rule, the loop, no-sidetrack,
   confirm-the-approach, honesty) — don't duplicate guardrails the project already states; cross-link the existing
   context doc instead of forking it.
3. **`project-profile` memory** (judgment): write the resolved slots — *the-real-thing / verify / evidence* and each
   slot's source profile (or the custom-elicited slots) — and add its pointer to the memory index, so
   `/verify-goodbehavior` and `/gate-build-goodbehavior` read "done" from it. For a custom fallback, also write the
   profile body into `<target>/.claude/goodbehavior/profiles/custom.md` (no core file to copy).
4. **Confirmed dev approach** (judgment; *only if a development slot is in play*): record in the target's CLAUDE.md
   `## Stack & conventions` + a `project` memory, so verify/gate-build use the agreed run/deploy/verify method.
5. **Seed memories** (judgment): `definition-of-done` (one line + pointer to the principles home — don't restate) +
   `reporting-honesty` + the `project-profile` from step 3; start an empty `build-deploy-gotchas`.

## Report
List exactly what was created / amended / skipped **in the target**, and where principles, skills, hook, plans, memory,
and the manifest now live. Note that the other commands (`/audit-goodbehavior`, `/roadmap-goodbehavior`,
`/gate-build-goodbehavior`, `/verify-goodbehavior`, `/learn-goodbehavior`, `/update-goodbehavior`) now run from a session
opened **in the target project** — its `.claude/skills/` holds the copies. Do NOT claim the method "works" — the
scaffolding is in place; it proves itself on the first real task via `/audit-goodbehavior` → `/roadmap-goodbehavior` →
`/gate-build-goodbehavior`.

> Source files (skills, hook, `templates/`, `scripts/`) ship with this bundle in its git repo. Resolve them from the
> **source** path recorded in (or about to be written to) the manifest. Prefer `scripts/install.py` for the mechanics;
> only fall back to manual copying if the script is missing (an old source), and then follow its guarantees by hand
> (never clobber; merge settings.json; hash into the manifest). Never install outside the target's `.claude/` (plus the
> confirmed planning/doc paths).
