---
name: update-goodbehavior
description: Pull the latest GoodBehavior bundle from its source repo and reconcile it into THIS project's local copy without losing local adaptations. For each tracked file, do a git 3-way merge (base = the commit recorded in the manifest, ours = the local file, theirs = the new upstream) via `git merge-file`. Untouched files fast-forward, adapted files merge, real conflicts get markers. Then rewrite the manifest. Human-in-the-loop on conflicts.
---

Update the local GoodBehavior copy from its source, preserving whatever this project adapted. The install is a copy (not
a symlink) precisely so a project can diverge; this skill is how divergence and upstream improvement are reconciled.
**Never overwrite a locally-adapted file blindly — merge it.**

## Pre-flight
1. Read `<project>/.claude/goodbehavior/manifest.json`. Missing → the project hasn't adopted GoodBehavior; tell the user
   to run `/adopt-goodbehavior` and stop.
2. Resolve `source`. If a local path, confirm it's a git repo. If a git URL, use the cached clone or clone it somewhere
   temporary. The source **must be a committed git repo** — the merge needs commit objects.
3. If `manifest.sourceCommit` is `null` (source had no commits at adopt time): there's no merge base. Offer the user
   either *overwrite-from-upstream* (back up each local file to `*.bak` first, then copy in fresh) or *abort*. Do not
   silently overwrite.
4. `git -C <source> fetch` if it has a remote. Determine the target commit `NEW` (default `git -C <source> rev-parse
   HEAD`; if tracking a remote, `origin/<branch>`). If `NEW == sourceCommit` → **"already up to date"**, stop.
5. If the source working tree has uncommitted changes, note it: base/theirs come from commits, so uncommitted source
   edits won't be included. Suggest committing the source first for a complete update.

## Reconcile each tracked file
For every entry in `manifest.files`, plus any file present in `NEW` under the bundle's tracked paths but not yet in the
manifest (an upstream **addition**):

1. **theirs** = `git -C <source> show <NEW>:<from>`. If the path no longer exists in `NEW` → upstream **removed** it; ask
   before deleting locally (default: keep + report).
2. **base** = `git -C <source> show <sourceCommit>:<from>`. If it didn't exist at base (new upstream file): if the target
   file is absent locally, copy theirs in (**added**); if it exists locally with no base, you can't 3-way it — if local
   == theirs it's **unchanged**, else write theirs beside it as `<file>.upstream` and flag (**needs manual merge**).
3. **ours** = the current target file `<project>/<key>`.
4. **Fast path** — if `sha256(ours)` equals the manifest's recorded `sha256` (untouched since install): overwrite with
   theirs → **updated**.
5. **3-way merge** otherwise: write base/ours/theirs to temp files and run
   ```sh
   git merge-file -p -L "local" -L "base" -L "upstream" <ours_tmp> <base_tmp> <theirs_tmp> > merged
   ```
   Exit 0 (clean) → write `merged` to the target → **merged**. Non-zero (conflicts) → the output still contains the file
   with `<<<<<<<`/`=======`/`>>>>>>>` markers; write it to the target, mark **conflict**, and list the file for the user.

**`settings.json` is special — never overwrite it.** It's project-owned and may carry the user's own hooks. Only update
`done-gate.py` itself. If the upstream `Stop`-hook wiring format changed, surface that as a note for the user to apply by
hand rather than rewriting their `settings.json`.

**`CLAUDE.md` principles** are tracked only if `/adopt` recorded them in the manifest. If not (they were appended as prose
into a project-owned CLAUDE.md), don't touch CLAUDE.md — just report that upstream principles changed and let the user
reconcile the wording.

## Finalize
- For each **updated**/**merged**/**added** file, refresh its `sha256` in the manifest to the new on-disk content.
- For **conflict** files, leave the old `sha256` and the markers in place — the user resolves them; a re-run then sees a
  clean file.
- Set `manifest.sourceCommit = NEW` and update `installedAt`/add `updatedAt` to now.

## Report
A table: **unchanged / updated / merged / conflict / added / removed**, with the old→new commit. If anything is in
**conflict** or **needs manual merge**, say so plainly and point at the files — do NOT report the update as complete.
Conflicts are resolved by the user, then `/update-goodbehavior` (or removing the markers) closes them out.

> Requires `git` and a reachable, committed source repo. Touches only files under the project's `.claude/` (and never
> `settings.json`'s contents beyond the done-gate wiring). When unsure whether a divergence is intentional, prefer a
> conflict marker over a silent overwrite — same human-in-the-loop principle as the done-gate.
