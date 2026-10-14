# GoodBehavior

A portable Claude Code bundle that installs a **disciplined working method** into any project: audit before building,
a gated build loop, verify the real thing (not a proxy), record learnings so they don't decay, and report honestly —
with a hook that pushes back on self-declared "done."

It's not project knowledge. It's a *way of working*, distilled from a real build where the recurring failure was
**false claims and lazy output** — passing a test or showing a screenshot and calling a half-built feature "done."

**Not dev-only.** The discipline is invariant across development, analysis, research, creative, and DevOps work — only what
"the real thing / verify / evidence" mean changes, and a lightweight **profile** captures that per project (composable
per-slot, with a custom fallback so it never declines a project). Adoption *asks what the project is* before sniffing
its files.

> **New here? Read the [TUTORIAL](TUTORIAL.md)** — install into a project (new or existing), turn intent into a plan +
> checklists, then build it down under the gated loop. It also shows exactly what does (and doesn't) land in your project.

## What's in it

| Piece | What it does | Type |
|---|---|---|
| `CLAUDE.md` | The operating principles (the persona). The definition of done, the loop, no-sidetrack, honesty. | guidance |
| `/adopt-goodbehavior` | **Entry point.** Elicits project intent, resolves a **profile** (dev/analysis/research/creative/devops, composable), analyzes the workflow, proposes tailored amendments (CLAUDE.md + skills + hook + plan/memory) with options, asks, then applies — integrating with existing docs (e.g. HANDOFF.md), not overwriting. | skill |
| `templates/profiles/` | The **profile** layer: what "the real thing / verify / evidence" mean per project type. Index + five core bodies, loaded on demand; only the resolved one installs into a project. `devops/` adds guides: a cross-cloud baseline (every rule with its live probe), then per-platform guides. | guidance |
| `/audit-goodbehavior` | Reference-cross-checked, grouped, gated gap register. | skill |
| `/roadmap-goodbehavior` | Rolls gaps into a phased, gated plan + backlog. | skill |
| `/gate-build-goodbehavior` | Executes one phase: build → verify live → record learnings → gate. | skill |
| `/verify-goodbehavior` | Exercises the real thing the way its consumer would (per the profile) + captures evidence. Self-contained. | skill |
| `/uatplan-goodbehavior` | Builds/maintains a living manual UAT plan — feature map + how to test each + pass/fail checklist. Feeds verify. | skill |
| `/learn-goodbehavior` | Writes a durable learning to memory (so it's not relearned). | skill |
| `/update-goodbehavior` | Pulls the latest bundle from its source repo and 3-way-merges it into the local copy, preserving project-local adaptations. | skill |
| `.claude/hooks/done-gate.py` + `.claude/settings.json` | Stop hook: pushes back on "done" without evidence — including *behaviorally*: verification vocabulary is honored only if something was actually run/observed after the last file change that turn. A profile can supply its own questions (devops: change vs investigation) and its own PreToolUse guard (devops: `guard.py` — reads run, changes ask, secrets are denied, fails closed, logs every decision). | enforcement |
| `scripts/install.py` · `scripts/update.py` | The mechanical halves of adopt/update, deterministic: copy+hash+wire+manifest, and the git 3-way merge. The skills keep the judgment; the scripts keep the consistency. | tooling |
| `tests/run_all.py` | The bundle held to its own standard: hook behavior, install round-trip, update merge paths, structural+drift lint, and every cloud CLI command in the devops guides parsed offline by the real CLI (skipped where a CLI isn't installed) — one command, all green before shipping. | self-test |

Guidance shapes intent; **only the hook enforces** when intent slips. That's the point — the method failed before
precisely because nothing stopped a lazy turn.

## Install into a project

The bundle is installed **as a project-local copy — never a symlink, never a global `~/.claude/` install.** Each project
owns its copy so it can adapt the principles/skills to its own stack without affecting other projects or your global
config. Updates come later from the source repo via a tracked 3-way merge (see below), not from a shared live source.

`/adopt-goodbehavior` is the **intelligent installer** — it lands the whole bundle itself; there's no blind copy step.
Open a session **in this GoodBehavior repo** (so the skills are loaded) and point adopt at the target:

```
/adopt-goodbehavior /path/to/your-project
```

It then **resolves** source (this bundle) and target (your project), **analyzes** the target's real workflow,
**proposes** tailored amendments (where principles live, the confirmed dev approach, planning/memory) **with options**,
**asks** before writing anything, and only then installs idempotently into the target's `.claude/` — copying the skills,
hook, and templates from the source, merging into existing docs/conventions rather than forking them, and recording
exactly what it installed in a manifest — the mechanical steps run through `scripts/install.py`, so every install is
identical. (`/adopt-goodbehavior` itself is **not** copied into targets — it's a run-once installer; targets carry the
working skills plus `/update-goodbehavior`.) After install, run the other `*-goodbehavior` commands from a session
opened **in the target project**.

## Stay current — `/update-goodbehavior`

Because the install is a copy (not a symlink), it won't drift as you improve the source. To pull improvements in without
losing the local adaptations a project has made, run **`/update-goodbehavior`**. It reads the manifest (which records the
source repo and the exact commit the copy derived from), fetches upstream, and for every tracked file does a **git
3-way merge** — base = the manifest commit, *ours* = the local file, *theirs* = the new upstream version:

- file untouched locally → fast-forwarded to upstream;
- file adapted locally → changes merged;
- genuine conflict → conflict markers written for you to resolve.

It then rewrites the manifest to the new commit. Self-updating, but human-in-the-loop on conflicts — the same principle
as the done-gate. (Requires the source to be a committed git repo so the merge base exists.)

## The honest caveat

A persona + skills can encode the rules, but the engine that made this work was a human catching slips and a habit of
writing down every lesson. The hook adds teeth, but it's a heuristic nudge, not a lie detector. Keep
**user-confirmation as the done-gate** — the method is human-in-the-loop by design, not an autopilot for honesty.

## Chat or a non-agentic assistant?

The bundle above is agentic — skills, a hook, a filesystem to verify against. To get the same posture in plain Claude.ai
chat (or another assistant like Copilot), [`chat-agents/`](chat-agents/) carries the discipline as prompt alone
(understanding gate, ✔/⚠ evidence tagging, no self-declared "done," a running ledger). Two ways to deploy it:
[`goodbehavior.md`](chat-agents/goodbehavior.md) as standing instructions (invoke with "follow the GoodBehavior
approach"); or — for assistants that **ignore** custom instructions — attach that file **and** drive each task with
[`PROMPT-TEMPLATE.md`](chat-agents/PROMPT-TEMPLATE.md), which re-states the rules inline where they can't be dropped.
Companion only — nothing installs it.

## License

[MIT](LICENSE) © 2026 Ronald Villaver.
