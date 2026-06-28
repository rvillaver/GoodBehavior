# GoodBehavior

A portable Claude Code bundle that installs a **disciplined working method** into any project: audit before building,
a gated build loop, verify the real thing (not a proxy), record learnings so they don't decay, and report honestly —
with a hook that pushes back on self-declared "done."

It's not project knowledge. It's a *way of working*, distilled from a real build where the recurring failure was
**false claims and lazy output** — passing a test or showing a screenshot and calling a half-built feature "done."

> **New here? Read the [TUTORIAL](TUTORIAL.md)** — install into a project (new or existing), turn intent into a plan +
> checklists, then build it down under the gated loop. It also shows exactly what does (and doesn't) land in your project.

## What's in it

| Piece | What it does | Type |
|---|---|---|
| `CLAUDE.md` | The operating principles (the persona). The definition of done, the loop, no-sidetrack, honesty. | guidance |
| `/adopt-goodbehavior` | **Entry point.** Analyzes the project's workflow, proposes tailored amendments (CLAUDE.md + skills + hook + plan/memory) with options, asks, then applies — integrating with existing docs (e.g. HANDOFF.md), not overwriting. | skill |
| `/audit-goodbehavior` | Reference-cross-checked, grouped, gated gap register. | skill |
| `/roadmap-goodbehavior` | Rolls gaps into a phased, gated plan + backlog. | skill |
| `/gate-build-goodbehavior` | Executes one phase: build → verify live → record learnings → gate. | skill |
| `/verify-goodbehavior` | Exercises the real behavior (UI + backend) + captures evidence. Self-contained. | skill |
| `/uatplan-goodbehavior` | Builds/maintains a living manual UAT plan — feature map + how to test each + pass/fail checklist. Feeds verify. | skill |
| `/learn-goodbehavior` | Writes a durable learning to memory (so it's not relearned). | skill |
| `/update-goodbehavior` | Pulls the latest bundle from its source repo and 3-way-merges it into the local copy, preserving project-local adaptations. | skill |
| `.claude/hooks/done-gate.py` + `.claude/settings.json` | Stop hook: when you claim "done" without evidence, it pushes back. | enforcement |

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
exactly what it installed in a manifest. (Already inside a project that has the skills? Run `/adopt-goodbehavior` with no
path to adopt the current project.) After install, run the other `*-goodbehavior` commands from a session opened **in the
target project**.

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
