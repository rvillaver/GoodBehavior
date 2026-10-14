#!/usr/bin/env python3
"""update.py 3-way-merge round-trip — hermetic mini-source repo, all four reconciliation paths:

  a.md  untouched locally, changed upstream        -> fast-forwarded ("updated")
  b.md  adapted locally, compatible upstream change -> cleanly merged ("merged")
  c.md  adapted locally, overlapping upstream change-> conflict markers ("conflict", exit 2)
  d.md  removed upstream                            -> kept locally, reported ("removed_upstream")

Then: manifest advanced to the new commit, and a re-run reports "already up to date"."""
import json, os, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTALL = os.path.join(ROOT, "scripts", "install.py")
UPDATE = os.path.join(ROOT, "scripts", "update.py")

BASE_BODY = "line1\nline2\nline3\nline4\nline5\n"


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t"] + list(args),
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {r.stderr}")
    return r.stdout


def write(repo, rel, content):
    p = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(content)


def main():
    failures = []

    def check(label, cond, detail=""):
        print(f"  {'PASS' if cond else 'FAIL'}  {label}")
        if not cond:
            failures.append(f"{label} {detail}")

    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "source")
        target = os.path.join(tmp, "target")
        os.makedirs(source)
        os.makedirs(target)

        # commit A — the install-time state
        git(source, "init", "-q")
        for name in "abcd":
            write(source, f"templates/{name}.md", BASE_BODY)
        git(source, "add", "-A")
        git(source, "commit", "-qm", "A")

        plan = {"source": source, "target": target, "skills": [], "profiles": [], "hook": False,
                "templates": {f"docs/{n}.md": f"templates/{n}.md" for n in "abcd"}}
        plan_path = os.path.join(tmp, "plan.json")
        with open(plan_path, "w") as f:
            json.dump(plan, f)
        r = subprocess.run([sys.executable, INSTALL, "--plan", plan_path], capture_output=True, text=True)
        check("install into target succeeded", r.returncode == 0, r.stderr)

        # local adaptations: b compatible (edit line5), c overlapping (edit line1 — upstream edits line1 too)
        write(target, "docs/b.md", BASE_BODY.replace("line5", "line5-LOCAL"))
        write(target, "docs/c.md", BASE_BODY.replace("line1", "line1-LOCAL"))

        # commit B — upstream evolves: a line3, b line1, c line1 (collides with local), d removed
        write(source, "templates/a.md", BASE_BODY.replace("line3", "line3-UPSTREAM"))
        write(source, "templates/b.md", BASE_BODY.replace("line1", "line1-UPSTREAM"))
        write(source, "templates/c.md", BASE_BODY.replace("line1", "line1-UPSTREAM"))
        git(source, "rm", "-q", "templates/d.md")
        git(source, "add", "-A")
        git(source, "commit", "-qm", "B")

        r = subprocess.run([sys.executable, UPDATE, "--target", target], capture_output=True, text=True)
        check("update exits 2 (completed WITH conflicts)", r.returncode == 2, r.stderr)
        report = json.loads(r.stdout)

        check("untouched file fast-forwarded", "docs/a.md" in report["updated"])
        with open(os.path.join(target, "docs/a.md")) as f:
            check("fast-forward took upstream content", "line3-UPSTREAM" in f.read())

        check("adapted file cleanly merged", "docs/b.md" in report["merged"])
        with open(os.path.join(target, "docs/b.md")) as f:
            b = f.read()
        check("merge kept BOTH local and upstream changes",
              "line5-LOCAL" in b and "line1-UPSTREAM" in b)

        check("overlapping edit conflicts", "docs/c.md" in report["conflict"])
        with open(os.path.join(target, "docs/c.md")) as f:
            c = f.read()
        check("conflict markers written for the human", "<<<<<<<" in c and ">>>>>>>" in c)

        check("upstream removal kept locally + reported",
              "docs/d.md" in report["removed_upstream"]
              and os.path.isfile(os.path.join(target, "docs/d.md")))

        with open(os.path.join(target, ".claude/goodbehavior/manifest.json")) as f:
            manifest = json.load(f)
        new_commit = git(source, "rev-parse", "HEAD").strip()
        check("manifest advanced to new commit", manifest["sourceCommit"] == new_commit)
        check("manifest updatedAt stamped", bool(manifest.get("updatedAt")))

        r2 = subprocess.run([sys.executable, UPDATE, "--target", target], capture_output=True, text=True)
        report2 = json.loads(r2.stdout)
        check("re-run reports already up to date",
              r2.returncode == 0 and report2["status"] == "already up to date")

        # a cleanly merged file keeps its local edits on the NEXT update too, even when upstream didn't change it
        # (regression: a recorded merged sha256 made the next run fast-forward the template over local edits)
        write(source, "templates/z.md", "unrelated\n")
        git(source, "add", "-A")
        git(source, "commit", "-qm", "unrelated")
        r_next = subprocess.run([sys.executable, UPDATE, "--target", target], capture_output=True, text=True)
        with open(os.path.join(target, "docs/b.md")) as f:
            b2 = f.read()
        check("merged file kept its local edits on the next update", "line5-LOCAL" in b2 and "line1-UPSTREAM" in b2,
              r_next.stdout[:200])
        check("merged file not reported as fast-forwarded", "docs/b.md" not in json.loads(r_next.stdout).get("updated", []))

        # a manifest that names the source as ~/... (portable, no machine-local path) still resolves
        mpath = os.path.join(target, ".claude/goodbehavior/manifest.json")
        with open(mpath) as f:
            m = json.load(f)
        stamped = m["updatedAt"]
        m["source"] = "~/source"
        with open(mpath, "w") as f:
            json.dump(m, f)
        write(source, "templates/a.md", BASE_BODY.replace("line4", "line4-C"))
        git(source, "commit", "-qam", "C")
        home = dict(os.environ, HOME=tmp)
        r3 = subprocess.run([sys.executable, UPDATE, "--target", target], capture_output=True, text=True, env=home)
        check("~ in manifest source is expanded", r3.returncode in (0, 2) and "not a git repo" not in r3.stdout,
              r3.stdout[:200])

        # re-running install (to add files) keeps the update stamp
        plan["templates"].pop("docs/d.md")  # removed upstream in commit B
        with open(plan_path, "w") as f:
            json.dump(plan, f)
        r4 = subprocess.run([sys.executable, INSTALL, "--plan", plan_path], capture_output=True, text=True)
        with open(mpath) as f:
            after = json.load(f)
        check("install keeps manifest updatedAt", r4.returncode == 0 and bool(after.get("updatedAt")),
              f"rc={r4.returncode} updatedAt={after.get('updatedAt')} r3={r3.stdout[:120]} err={r4.stderr[:200]}")

    print(f"test_update: {'FAILED: ' + '; '.join(failures) if failures else 'all passed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
