#!/usr/bin/env python3
"""install.py round-trip test — installs the REAL bundle into a temp target and checks the guarantees:
only the planned profiles land (never all five), the manifest records true sha256s, settings.json merges
without duplication, existing files are never clobbered, and a re-run is a clean no-op."""
import hashlib, json, os, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTALL = os.path.join(ROOT, "scripts", "install.py")


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def run_install(plan_path):
    r = subprocess.run([sys.executable, INSTALL, "--plan", plan_path], capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"install.py failed: {r.stderr}")
    return json.loads(r.stdout)


def main():
    failures = []

    def check(label, cond, detail=""):
        print(f"  {'PASS' if cond else 'FAIL'}  {label}")
        if not cond:
            failures.append(f"{label} {detail}")

    with tempfile.TemporaryDirectory() as target:
        # a fake existing project file that must never be clobbered
        os.makedirs(os.path.join(target, ".claude", "skills", "verify-goodbehavior"))
        sentinel = os.path.join(target, ".claude", "skills", "verify-goodbehavior", "SKILL.md")
        with open(sentinel, "w") as f:
            f.write("LOCAL ADAPTATION — do not clobber\n")
        # a pre-existing settings.json with the user's own hook that must survive the merge
        with open(os.path.join(target, ".claude", "settings.json"), "w") as f:
            json.dump({"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "echo mine"}]}]}}, f)

        plan = {"source": ROOT, "target": target,
                "skills": ["verify-goodbehavior", "learn-goodbehavior", "update-goodbehavior"],
                "profiles": ["analysis", "development"],
                "hook": True,
                "templates": {"docs/plans/ROADMAP.md": "templates/ROADMAP.md"}}
        plan_path = os.path.join(target, "plan.json")
        with open(plan_path, "w") as f:
            json.dump(plan, f)

        report = run_install(plan_path)

        check("planned skills copied",
              os.path.isfile(os.path.join(target, ".claude/skills/learn-goodbehavior/SKILL.md")))
        check("planned profiles copied",
              os.path.isfile(os.path.join(target, ".claude/goodbehavior/profiles/analysis.md"))
              and os.path.isfile(os.path.join(target, ".claude/goodbehavior/profiles/development.md")))
        check("UNplanned profiles absent (minimal footprint)",
              not os.path.exists(os.path.join(target, ".claude/goodbehavior/profiles/creative.md"))
              and not os.path.exists(os.path.join(target, ".claude/goodbehavior/profiles/research.md")))
        check("template landed", os.path.isfile(os.path.join(target, "docs/plans/ROADMAP.md")))
        check("hook landed executable",
              os.access(os.path.join(target, ".claude/hooks/done-gate.py"), os.X_OK))
        with open(sentinel) as f:
            check("existing file never clobbered", "LOCAL ADAPTATION" in f.read())
        check("clobber-skip reported",
              any("verify-goodbehavior" in s for s in report["skipped"]))

        mpath = os.path.join(target, ".claude/goodbehavior/manifest.json")
        with open(mpath) as f:
            manifest = json.load(f)
        check("manifest has sourceCommit", bool(manifest.get("sourceCommit")))
        hashes_ok = all(sha256(os.path.join(target, k)) == v["sha256"]
                        for k, v in manifest["files"].items())
        check("manifest sha256s match files as installed", hashes_ok)
        check("manifest tracks the installed profiles",
              ".claude/goodbehavior/profiles/analysis.md" in manifest["files"])

        with open(os.path.join(target, ".claude", "settings.json")) as f:
            settings = json.load(f)
        check("user's own hook preserved", "PostToolUse" in settings["hooks"])
        stops = settings["hooks"].get("Stop", [])
        wired = sum(1 for e in stops for h in e.get("hooks", []) if "done-gate" in h.get("command", ""))
        check("Stop hook wired exactly once", wired == 1)
        pre = settings["hooks"].get("PreToolUse", [])
        guard = [e for e in pre for h in e.get("hooks", []) if "done-gate" in h.get("command", "")]
        check("no PreToolUse wiring for profiles without a guard (analysis, development)", not guard)

        # idempotency: re-run must create nothing new and not double-wire
        report2 = run_install(plan_path)
        check("re-run creates nothing", report2["created"] == [])
        with open(os.path.join(target, ".claude", "settings.json")) as f:
            stops2 = json.load(f)["hooks"]["Stop"]
        wired2 = sum(1 for e in stops2 for h in e.get("hooks", []) if "done-gate" in h.get("command", ""))
        check("re-run does not double-wire the hook", wired2 == 1)
        with open(os.path.join(target, ".claude", "settings.json")) as f:
            pre2 = json.load(f)["hooks"].get("PreToolUse", [])
        check("re-run adds no PreToolUse wiring", not [e for e in pre2 for h in e.get("hooks", [])
                                                       if "done-gate" in h.get("command", "")])

    # profile guides: a nested <profile>/<guide> entry lands under profiles/, tracked with its source path
    with tempfile.TemporaryDirectory() as target:
        plan_path = os.path.join(target, "plan.json")
        with open(plan_path, "w") as f:
            json.dump({"source": ROOT, "target": target, "skills": [],
                       "profiles": ["devops", "devops/baseline", "devops/guard.py"], "hook": False, "templates": {}}, f)
        run_install(plan_path)
        guide = os.path.join(target, ".claude/goodbehavior/profiles/devops/baseline.md")
        check("guide copied byte-identical",
              os.path.isfile(guide) and sha256(guide) == sha256(os.path.join(ROOT, "templates/profiles/devops/baseline.md")))
        with open(os.path.join(target, ".claude/goodbehavior/manifest.json")) as f:
            entry = json.load(f)["files"].get(".claude/goodbehavior/profiles/devops/baseline.md", {})
        check("manifest tracks the guide's source path", entry.get("from") == "templates/profiles/devops/baseline.md")
        g = os.path.join(target, ".claude/goodbehavior/profiles/devops/guard.py")
        plan_hook = {"source": ROOT, "target": target, "skills": [], "profiles": ["devops", "devops/guard.py"],
                     "hook": True, "templates": {}}
        with open(plan_path, "w") as f:
            json.dump(plan_hook, f)
        run_install(plan_path)
        run_install(plan_path)  # re-run must not double-wire
        with open(os.path.join(target, ".claude", "settings.json")) as f:
            pre = json.load(f)["hooks"].get("PreToolUse", [])
        wired = [e for e in pre for h in e.get("hooks", []) if "done-gate" in h.get("command", "")]
        check("devops: PreToolUse guard wired exactly once, on every tool", len(wired) == 1 and wired[0].get("matcher") == "*")
        check("guard.py installed as-is (no .md added)",
              os.path.isfile(g) and sha256(g) == sha256(os.path.join(ROOT, "templates/profiles/devops/guard.py")))

    print(f"test_install: {'FAILED: ' + '; '.join(failures) if failures else 'all passed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
