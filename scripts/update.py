#!/usr/bin/env python3
"""GoodBehavior deterministic updater — the mechanical half of /update-goodbehavior.

Reads the target's manifest, resolves the source repo, and reconciles every tracked file with a
git 3-way merge: base = the commit recorded in the manifest, ours = the local file, theirs = the
new upstream version. Untouched files fast-forward; adapted files merge; genuine conflicts get
markers for the human. The skill keeps the JUDGMENT (deciding about upstream additions/removals,
resolving conflicts with the user); this script does the merge mechanics identically every run.

Usage:
    python3 scripts/update.py --target /path/to/project [--source /override/path] [--dry-run]

Guarantees:
  - never touches settings.json (project-owned; may carry the user's own hooks)
  - a file whose sha256 matches the manifest (untouched since install) is fast-forwarded
  - an adapted file is 3-way merged; conflicts are written WITH markers and reported, and their
    manifest sha256 is left stale so a re-run after resolution treats them cleanly
  - files upstream REMOVED are kept locally and reported (deleting is the skill/user's call)
  - manifest sourceCommit/updatedAt/sha256s refreshed for everything cleanly updated or merged
Reports JSON on stdout:
  {"status": "...", "unchanged": [], "updated": [], "merged": [], "conflict": [],
   "restored": [], "removed_upstream": [], "warnings": []}
Exit code: 0 clean (even if already up to date), 1 fatal, 2 completed WITH conflicts.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile
from datetime import datetime, timezone


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def git(source, *args, binary=False):
    out = subprocess.run(["git", "-C", source] + list(args), capture_output=True)
    if out.returncode != 0:
        return None
    return out.stdout if binary else out.stdout.decode()


def git_show(source, commit, path):
    return git(source, "show", f"{commit}:{path}", binary=True)


def merge_file(ours, base, theirs):
    """git merge-file on byte content. Returns (merged_bytes, clean)."""
    with tempfile.TemporaryDirectory() as d:
        po, pb, pt = (os.path.join(d, n) for n in ("ours", "base", "theirs"))
        for p, content in ((po, ours), (pb, base), (pt, theirs)):
            with open(p, "wb") as f:
                f.write(content)
        r = subprocess.run(["git", "merge-file", "-p", "-L", "local", "-L", "base", "-L", "upstream",
                            po, pb, pt], capture_output=True)
        return r.stdout, r.returncode == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--source", help="override the manifest's source path")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    target = os.path.abspath(os.path.expanduser(args.target))
    manifest_path = os.path.join(target, ".claude", "goodbehavior", "manifest.json")
    if not os.path.isfile(manifest_path):
        print(json.dumps({"status": "no manifest — run /adopt-goodbehavior first"}))
        return 1
    with open(manifest_path) as f:
        manifest = json.load(f)

    source = os.path.abspath(os.path.expanduser(args.source or manifest["source"]))
    if not os.path.isdir(os.path.join(source, ".git")):
        print(json.dumps({"status": f"source is not a git repo: {source}"}))
        return 1
    base_commit = manifest.get("sourceCommit")
    if not base_commit:
        print(json.dumps({"status": "manifest sourceCommit is null — no merge base; "
                                    "re-adopt or overwrite manually (never silently)"}))
        return 1
    new_commit = (git(source, "rev-parse", "HEAD") or "").strip()
    if not new_commit:
        print(json.dumps({"status": "could not resolve source HEAD"}))
        return 1
    if new_commit == base_commit:
        print(json.dumps({"status": "already up to date", "commit": new_commit}))
        return 0

    report = {"status": f"{base_commit[:8]} -> {new_commit[:8]}", "unchanged": [], "updated": [],
              "merged": [], "conflict": [], "restored": [], "removed_upstream": [], "warnings": []}

    for key, entry in sorted(manifest.get("files", {}).items()):
        src_rel = entry["from"]
        theirs = git_show(source, new_commit, src_rel)
        if theirs is None:
            report["removed_upstream"].append(key)
            continue
        local_path = os.path.join(target, key)
        if not os.path.isfile(local_path):
            if not args.dry_run:
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                with open(local_path, "wb") as f:
                    f.write(theirs)
                entry["sha256"] = sha256_bytes(theirs)
            report["restored"].append(key)
            continue
        with open(local_path, "rb") as f:
            ours = f.read()
        if ours == theirs:
            entry["sha256"] = sha256_bytes(ours)
            report["unchanged"].append(key)
            continue
        base = git_show(source, base_commit, src_rel)
        # Untouched = identical to the upstream version it came from. Compare with that version itself, not only the
        # recorded sha256: an older update.py recorded the *merged* content after a clean merge, and trusting that
        # sha alone made the next update overwrite local edits with the template.
        untouched = ours == base if base is not None else sha256_bytes(ours) == entry.get("sha256")
        if untouched:
            if not args.dry_run:
                with open(local_path, "wb") as f:
                    f.write(theirs)
                entry["sha256"] = sha256_bytes(theirs)
            report["updated"].append(key)
            continue
        if base is None:
            report["warnings"].append(f"{key}: no base at {base_commit[:8]} — left as-is; merge by hand")
            continue
        merged, clean = merge_file(ours, base, theirs)
        if not args.dry_run:
            with open(local_path, "wb") as f:
                f.write(merged)
            # the manifest records the upstream version at sourceCommit, never the local or merged content, so the
            # next update still sees the local edits and merges them instead of fast-forwarding over them
            entry["sha256"] = sha256_bytes(theirs)
        report["merged" if clean else "conflict"].append(key)

    if not args.dry_run:
        manifest["sourceCommit"] = new_commit
        manifest["updatedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")

    json.dump(report, sys.stdout, indent=2)
    print()
    return 2 if report["conflict"] else 0


if __name__ == "__main__":
    sys.exit(main())
