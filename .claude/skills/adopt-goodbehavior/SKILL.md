---
name: adopt-goodbehavior
description: Adopt the GoodBehavior method into a destination project — given a target path (or the current project), analyze its current workflow & conventions, propose tailored amendments (base CLAUDE.md, skills, done-gate hook, plan/memory scaffolding) WITH OPTIONS, get the user's confirmation, then install them idempotently INTO the target — copying the bundle (skills/hook/templates) from the GoodBehavior source itself. The intelligent installer & entry point; it integrates with what's already there instead of imposing a parallel structure.
---

Bring the disciplined method into a destination project by **adapting to it, not overwriting it**. adopt is the
*intelligent installer*: run it from the GoodBehavior source session and point it at **another project by path**, or run
it inside a project that already has the skills to adopt the current one. Four phases: resolve → analyze → propose (ask)
→ execute. **Change nothing in the target until the user confirms the plan.**

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

## Phase 1 — Analyze the TARGET (read the repo; don't assume)
Survey and report what's actually in the **target project**:
- **Stack & platform** — language(s), package manager, framework, services (e.g. Supabase/Deno, Docker, serverless, a
  monorepo with several apps).
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

## Phase 2 — Propose & ASK (still no execution)
Present a concrete adoption plan grounded in Phase 1, then ask the user to choose. Use `AskUserQuestion` for the real
decisions; recommend a default for each, and make clear nothing is written to the target until they confirm:
- **Principles home** — new `CLAUDE.md` · append to an existing CLAUDE.md · or link the principles from the existing
  context doc (e.g. `HANDOFF.md`) so there's no competing source of truth.
- **Dev approach (confirm, don't default — and don't conflate run-locally with verify-done).** Confirm the three facets
  from Phase 1 *separately*: (a) the local dev/test commands, (b) the **deploy trigger** (e.g. "push to `develop` →
  Railway + CI auto-deploy" vs a manual deploy command; containerized or not), and (c) **what `verify live` runs
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

## Phase 3 — Execute INTO the target (only after confirmation; idempotent)
Apply the confirmed plan into `<target>/`, copying bundle files **from `<source>/`**; never clobber — merge / append /
skip, and report created vs amended vs skipped:
1. **Principles** into the chosen home in the target (the core rule, the loop, no-sidetrack, confirm-the-approach,
   honesty) — don't duplicate guardrails the project already states; cross-link the existing context doc instead of
   forking it.
2. **Record the confirmed dev approach** in the target's CLAUDE.md `## Stack & conventions` + a `project` memory, so
   `/verify-goodbehavior` and `/gate-build-goodbehavior` use the agreed method.
3. **Copy the skills** from `<source>/.claude/skills/*-goodbehavior/` → `<target>/.claude/skills/` if not already present
   — copies, not symlinks. Include `/update-goodbehavior` so the project can self-update.
4. **Install the done-gate hook** (if chosen): copy `<source>/.claude/hooks/done-gate.py` → `<target>/.claude/hooks/` and
   wire the `Stop` hook in `<target>/.claude/settings.json` (merge, don't overwrite existing hooks). Make it executable.
5. **Planning + memory**: create from `<source>/templates/` into the target, or map per the choices; seed
   `definition-of-done` + `reporting-honesty`; start an empty `build-deploy-gotchas`.
6. **Write the manifest** at `<target>/.claude/goodbehavior/manifest.json` so `/update-goodbehavior` can reconcile later.
   Record the source and the exact commit the copy derived from, plus a hash per installed file:
   ```json
   {
     "source": "<abs path or git URL of the GoodBehavior source>",
     "sourceCommit": "<git -C <source> rev-parse HEAD>",
     "installedAt": "<ISO timestamp>",
     "files": {
       ".claude/skills/adopt-goodbehavior/SKILL.md": { "from": ".claude/skills/adopt-goodbehavior/SKILL.md", "sha256": "<hash at install>" }
       // …one entry per copied skill file + done-gate.py + any templates installed
     }
   }
   ```
   `from` is the path within the source repo; the key is the path within the **target**. The `sha256` (hash of the file
   *as installed*) lets update tell an untouched file from a locally-adapted one. If the source has **no commits yet**,
   record `"sourceCommit": null` and warn that `/update-goodbehavior` can't 3-way-merge until the source is committed.

## Report
List exactly what was created / amended / skipped **in the target**, and where principles, skills, hook, plans, memory,
and the manifest now live. Note that the other commands (`/audit-goodbehavior`, `/roadmap-goodbehavior`,
`/gate-build-goodbehavior`, `/verify-goodbehavior`, `/learn-goodbehavior`, `/update-goodbehavior`) now run from a session
opened **in the target project** — its `.claude/skills/` holds the copies. Do NOT claim the method "works" — the
scaffolding is in place; it proves itself on the first real task via `/audit-goodbehavior` → `/roadmap-goodbehavior` →
`/gate-build-goodbehavior`.

> Source files (skills, hook, `templates/`) ship with this bundle in its git repo. Resolve them from the **source** path
> recorded in (or about to be written to) the manifest — copy from there into the target. If the source isn't reachable,
> recreate the hook/templates from the references above (they're small). Never install outside the target's `.claude/`.
