#!/usr/bin/env python3
"""GoodBehavior deterministic installer — the mechanical half of /adopt-goodbehavior.

The adopt skill does the JUDGMENT (elicit intent, resolve the profile, propose, get confirmation)
and then hands this script a plan; this script does the MECHANICS exactly the same way every time:
copy files, hash them, wire the hook, write the manifest. Prompted models re-improvise procedures;
installs must not.

Usage:
    python3 scripts/install.py --plan plan.json          # execute
    python3 scripts/install.py --plan plan.json --dry-run

Plan format (written by the adopt skill after the user confirms):
{
  "source": "/abs/path/to/GoodBehavior",
  "target": "/abs/path/to/project",
  "skills":   ["audit-goodbehavior", "verify-goodbehavior", ...],   # skill DIR names to copy
  "profiles": ["analysis", "development"],   # ONLY the matched profile(s) — never all five;
                                             # guides go as "<profile>/<guide>", e.g. "devops/baseline"
  "hook": true,                              # install done-gate.py + wire Stop (and PreToolUse(*) for a
                                             # profile with a guard, e.g. devops)
  "templates": { "docs/plans/ROADMAP.md": "templates/ROADMAP.md", ... }   # target-rel -> source-rel
}

Guarantees:
  - never clobbers: an existing target file is skipped and reported (idempotent re-runs)
  - installs only under <target>/ (skills/hook/goodbehavior under .claude/, plus planned templates)
  - settings.json is merged, never overwritten; an existing Stop entry for done-gate is not duplicated
  - manifest at <target>/.claude/goodbehavior/manifest.json records source, sourceCommit and a
    sha256 per file AS INSTALLED (merged with any existing manifest)
Reports JSON on stdout: {"created": [...], "skipped": [...], "warnings": [...]}.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys
from datetime import datetime, timezone

HOOK_REL = ".claude/hooks/done-gate.py"
HOOK_CMD = 'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/done-gate.py"'


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def source_commit(source):
    try:
        out = subprocess.run(["git", "-C", source, "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return None


def plan_files(plan):
    """Yield (target_rel, source_rel) for every file the plan installs (hook/settings handled apart)."""
    src = plan["source"]
    for skill in plan.get("skills", []):
        skill_dir = os.path.join(src, ".claude", "skills", skill)
        if not os.path.isdir(skill_dir):
            raise SystemExit(f"error: skill not found in source: {skill}")
        for root, _, files in os.walk(skill_dir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, src)
                yield rel, rel
    for profile in plan.get("profiles", []):
        name = profile if os.path.splitext(profile)[1] else f"{profile}.md"  # e.g. "devops/guard.py" as-is
        src_rel = os.path.join("templates", "profiles", name)
        if not os.path.isfile(os.path.join(src, src_rel)):
            raise SystemExit(f"error: profile not found in source: {profile}")
        yield os.path.join(".claude", "goodbehavior", "profiles", name), src_rel
    for tgt_rel, src_rel in plan.get("templates", {}).items():
        if not os.path.isfile(os.path.join(src, src_rel)):
            raise SystemExit(f"error: template not found in source: {src_rel}")
        yield tgt_rel, src_rel
    if plan.get("hook"):
        yield HOOK_REL, HOOK_REL


def needs_guard(plan):
    """True when a planned profile ships a guard (guard.py) or gate rules (a "### gate:" section). Only those
    profiles (today: devops) get the PreToolUse wiring; the others get the Stop hook alone."""
    for profile in plan.get("profiles", []):
        name = profile if os.path.splitext(profile)[1] else f"{profile}.md"
        path = os.path.join(plan["source"], "templates", "profiles", name)
        if name.endswith("guard.py"):
            return True
        try:
            with open(path, encoding="utf-8") as f:
                if "### gate:" in f.read():
                    return True
        except OSError:
            pass
    return False


def wire_settings(target, dry_run, report, guard=True):
    """Merge the hook wiring into <target>/.claude/settings.json without touching anything else: Stop always,
    PreToolUse on every tool only when `guard` (a planned profile ships a guard). Each event is wired once; an
    existing done-gate entry is left alone."""
    path = os.path.join(target, ".claude", "settings.json")
    settings = {}
    if os.path.isfile(path):
        try:
            with open(path) as f:
                settings = json.load(f)
        except Exception:
            report["warnings"].append(f"settings.json exists but is not valid JSON — left untouched: {path}")
            return
    added = []
    for event, matcher in (("Stop", None), ("PreToolUse", "*"))[: 2 if guard else 1]:
        entries = settings.setdefault("hooks", {}).setdefault(event, [])
        if any("done-gate.py" in h.get("command", "") for e in entries for h in e.get("hooks", [])):
            report["skipped"].append(f".claude/settings.json ({event} hook already wired)")
            continue
        entry = {"hooks": [{"type": "command", "command": HOOK_CMD}]}
        if matcher:
            entry = {"matcher": matcher, **entry}
        entries.append(entry)
        added.append(event)
    if not added:
        return
    if not dry_run:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")
    report["created"].append(f".claude/settings.json ({' + '.join(added)} hook wired)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", required=True, help="path to the plan JSON")
    ap.add_argument("--dry-run", action="store_true", help="report what would happen; write nothing")
    args = ap.parse_args()

    with open(args.plan) as f:
        plan = json.load(f)
    source, target = (os.path.abspath(os.path.expanduser(plan[k])) for k in ("source", "target"))
    if source == target:
        raise SystemExit("error: refusing to install the source into itself")
    if not os.path.isdir(source):
        raise SystemExit(f"error: source not found: {source}")
    if not os.path.isdir(target):
        raise SystemExit(f"error: target not found: {target}")

    report = {"created": [], "skipped": [], "warnings": []}
    commit = source_commit(source)
    if commit is None:
        report["warnings"].append(
            "source has no git commit — sourceCommit=null; /update-goodbehavior cannot 3-way-merge "
            "until the source is committed")

    manifest_path = os.path.join(target, ".claude", "goodbehavior", "manifest.json")
    manifest = {"source": source, "sourceCommit": commit,
                "installedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "updatedAt": None, "files": {}}
    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path) as f:
                existing = json.load(f)
            manifest["files"] = existing.get("files", {})
            manifest["installedAt"] = existing.get("installedAt", manifest["installedAt"])
            manifest["updatedAt"] = existing.get("updatedAt")
        except Exception:
            report["warnings"].append("existing manifest was unreadable — rebuilding it")

    for tgt_rel, src_rel in plan_files(plan):
        dst = os.path.join(target, tgt_rel)
        if os.path.exists(dst):
            report["skipped"].append(tgt_rel)
            continue
        if not args.dry_run:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(source, src_rel), dst)
            if tgt_rel == HOOK_REL:
                os.chmod(dst, 0o755)
            manifest["files"][tgt_rel] = {"from": src_rel.replace(os.sep, "/"), "sha256": sha256(dst)}
        report["created"].append(tgt_rel)

    if plan.get("hook"):
        wire_settings(target, args.dry_run, report, guard=needs_guard(plan))

    if not args.dry_run:
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")

    json.dump(report, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
