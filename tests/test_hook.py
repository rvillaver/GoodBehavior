#!/usr/bin/env python3
"""done-gate.py behavior tests — drive the hook as a real subprocess with synthetic transcripts.

Each case builds a JSONL transcript (human turn -> assistant tool uses -> final assistant text),
pipes the Stop-hook stdin JSON, and asserts the exit code (0 = stop allowed, 2 = blocked) and,
when blocked, which message fired (bare-claim vs hollow-proof)."""
import glob, json, os, re, shutil, subprocess, sys, tempfile

HOOK = os.path.join(os.path.dirname(__file__), "..", ".claude", "hooks", "done-gate.py")
DEVOPS = os.path.join(os.path.dirname(__file__), "..", "templates", "profiles", "devops.md")


def entry_human(text):
    return {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}}


def entry_tool(name, tool_input=None):
    return {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "name": name, "input": tool_input or {}}]}}


def entry_text(text):
    return {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "text", "text": text}]}}


def run_hook(tools, final_text, stop_hook_active=False, project_dir=""):
    entries = [entry_human("please do the task")]
    entries += [entry_tool(n, i) for n, i in tools]
    entries.append(entry_text(final_text))
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
        path = f.name
    try:
        env = dict(os.environ, CLAUDE_PROJECT_DIR=project_dir)  # hermetic: never the caller's project
        r = subprocess.run([sys.executable, HOOK], env=env,
                           input=json.dumps({"transcript_path": path,
                                             "stop_hook_active": stop_hook_active}),
                           capture_output=True, text=True)
        return r.returncode, r.stderr
    finally:
        os.unlink(path)


EDIT_CODE = ("Edit", {"file_path": "src/app.py"})
EDIT_DOC = ("Edit", {"file_path": "README.md"})
BASH = ("Bash", {"command": "pytest -q"})
BROWSER = ("mcp__browser__navigate", {"url": "http://localhost:3000"})

CASES = [
    # (label, tools, final_text, expect_exit, expect_msg_fragment_or_None)
    ("discussion turn, bare claim -> allowed (activity gate)",
     [], "Done. The feature is complete.", 0, None),
    ("edited code, bare 'Done.' -> blocked (no evidence)",
     [EDIT_CODE], "Done. The feature is complete.", 2, "claimed completion"),
    ("edited code, 'verified' but ran NOTHING -> blocked (hollow proof)",
     [EDIT_CODE], "Done — I verified it works.", 2, "ran/observed NOTHING"),
    ("'confirmed' cheat with zero observation -> blocked (hollow proof)",
     [EDIT_CODE], "Complete. I confirm everything is correct.", 2, "ran/observed NOTHING"),
    ("edit then bash, 'tests pass' -> allowed (proof backed by behavior)",
     [EDIT_CODE, BASH], "Done — I ran the tests and they pass.", 0, None),
    ("bash BEFORE last edit, 'verified' -> blocked (final state never observed)",
     [BASH, EDIT_CODE], "Done — verified earlier, all good to go.", 2, "ran/observed NOTHING"),
    ("edit then browser drive, 'verified' -> allowed (browser counts as observing)",
     [EDIT_CODE, BROWSER], "Done — verified in the browser.", 0, None),
    ("doc-only edit, 'verified' -> allowed (nothing to run for prose)",
     [EDIT_DOC], "Done — reworded the section, verified the links.", 0, None),
    ("doc-only edit, bare 'Done.' -> still blocked (lexical layer holds)",
     [EDIT_DOC], "Done. All finished.", 2, "claimed completion"),
    ("honest hedge -> always allowed",
     [EDIT_CODE], "The code is written but not yet verified live.", 0, None),
    ("hedge with completion word -> allowed (honesty never punished)",
     [EDIT_CODE], "Done with the edits, but this is unverified — needs a live run.", 0, None),
    ("bash-only turn, 'confirmed' -> allowed (execution is itself observation)",
     [BASH], "Done — migration ran, confirmed row counts.", 0, None),
    ("meta discussion about the gate -> allowed",
     [EDIT_CODE], "The done-gate is now stricter. Done.", 0, None),
    ("stop_hook_active guard -> allowed (no loop)",
     [EDIT_CODE], "Done. The feature is complete.", 0, None),
]


EDIT_TF = ("Edit", {"file_path": "infra/main.tf"})
TF_APPLY = ("Bash", {"command": "terraform apply tfplan"})
TF_PLAN = ("Bash", {"command": "terraform plan -detailed-exitcode"})
READ_PROBE = ("Bash", {"command": "nc -zv db.internal 5432"})

# devops profile installed: the profile's own questions replace the generic self-check
DEVOPS_CASES = [
    ("devops: edited .tf, bare 'Done.' -> change questions",
     [EDIT_TF], "Done. The VPC is updated.", 2, "read the whole plan"),
    ("devops: bash-only apply, bare claim -> change questions (match: command)",
     [TF_APPLY], "Applied. All done.", 2, "saved, reviewed plan file"),
    ("devops: read-only probes, 'root cause' claim -> investigation questions",
     [READ_PROBE], "The root cause is the security group.", 2, "which are inference"),
    ("devops: read-only plan run, 'done' -> investigation (plan is not a change)",
     [TF_PLAN], "Done. Nothing to change.", 2, "symptom"),
    ("devops: investigation backed by an observation -> allowed",
     [READ_PROBE], "Root cause: port 5432 blocked, confirmed with nc.", 0, None),
    ("devops: edited .tf, 'verified' with nothing run -> hollow proof + change questions",
     [EDIT_TF], "Done — verified.", 2, "Also answer (change)"),
    ("devops: honest hedge -> allowed",
     [EDIT_TF], "The plan is written but not yet applied.", 0, None),
]


# guard (PreToolUse): with devops installed, commands that change infrastructure must ask the user first
GUARD_ASK = [
    "terraform apply tfplan", "terraform -chdir=infra apply", "tofu destroy -auto-approve",
    "terraform state rm aws_instance.x", "terraform import aws_s3_bucket.b b", "pulumi up",
    "aws ec2 terminate-instances --instance-ids i-1", "aws s3 rm s3://b/k", "aws iam attach-role-policy --role-name r",
    "aws cloudformation deploy --template t", "aws rds modify-db-instance --db-instance-identifier d",
    "az group delete -n rg", "az vm deallocate -g rg -n vm", "az network nsg rule create -g rg",
    "az deployment group create -g rg", "gcloud compute instances delete vm", "gcloud run deploy svc",
    "gcloud projects add-iam-policy-binding p", "doctl compute droplet delete 123", "doctl kubernetes cluster create c",
    "kubectl apply -f x.yaml", "kubectl -n prod delete pod p", "kubectl rollout restart deploy/x",
    "kubectl scale deploy/x --replicas=0", "helm upgrade app chart", "ansible-playbook site.yml",
    "sudo systemctl restart nginx", "ssh host sudo reboot",
    "qm stop 101", "qm rollback 101 snap1", "govc vm.power -off vm1", "virsh destroy vm1",
    "restic forget --keep-daily 7 --prune", "restic restore latest --target /tmp/r", "borg prune -v repo",
    "ha-manager migrate vm:101 node2",
]
GUARD_PASS = [
    "terraform plan -out tfplan", "terraform show tfplan", "terraform state list", "terraform validate",
    "aws ec2 describe-instances", "aws s3 ls", "aws sts get-caller-identity", "az vm list",
    "az network nsg rule list -g rg --nsg-name n", "az account show", "gcloud compute instances list",
    "doctl compute droplet list", "kubectl get pods", "kubectl describe pod p", "kubectl logs p", "helm list",
    "ansible-playbook site.yml --check --diff", "dig +short x", "curl -sI https://x", "git status", "pytest -q",
    "qm listsnapshot 101", "qm list", "govc snapshot.tree -vm vm1", "virsh list --all", "restic snapshots --latest 1",
    "restic check", "borg list --last 1 repo", "ha-manager status",
]


GUIDE_CLI = re.compile(r"(aws|az|gcloud|doctl|terraform|tofu|kubectl|helm|restic|borg|qm|govc|virsh) ")


def guide_probe_commands():
    """(read_only, changing) CLI commands from the devops guides' probes. A command written after a
    '(pause point)' marker changes something and must ask; one before it is read-only and must not."""
    read_only, changing = [], []
    for g in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "..", "templates", "profiles", "devops", "*.md"))):
        for block in re.split(r"\n- \*\*rule:\*\*", open(g).read())[1:]:
            probe = block.split("**probe:**", 1)[-1]
            i = probe.find("pause point")
            before, after = (probe, "") if i < 0 else (probe[:i], probe[i:])
            read_only += [c for c in re.findall(r"`([^`]+)`", before) if GUIDE_CLI.match(c)]
            changing += [c for c in re.findall(r"`([^`]+)`", after) if GUIDE_CLI.match(c)]
    return read_only, changing


def run_guard(command, project_dir):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=project_dir)
    r = subprocess.run([sys.executable, HOOK], env=env, capture_output=True, text=True,
                       input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                         "tool_input": {"command": command}}))
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    return r.returncode, out.get("hookSpecificOutput", {}).get("permissionDecision", "pass")


# A project with a Makefile, scripts and secret files: the guard must see through wrappers and protect secrets.
PROJECT_FILES = {
    "Makefile": "-include .secret\nTF = terraform -chdir=IaC/env/dr\n\ninfra_plan: guard\n\t$(TF) plan\n"
                "infra_apply: guard\n\t$(TF) apply tfplan\ndeploy: infra_apply\nrelease:\n\t$(MAKE) deploy\n"
                "guard:\n\t@echo checking account\ntest:\n\t./scripts/run-tests.sh\nlaunch:\n\tbash scripts/launch.sh\n",
    "scripts/launch.sh": "#!/bin/sh\n# starts replication\naws mgn start-replication --source-server-id s-1\n",
    "scripts/nested.sh": "#!/bin/sh\n./scripts/launch.sh\n",
    "scripts/run-tests.sh": "#!/bin/sh\nterraform test\n",
    "scripts/safe.sh": "#!/bin/sh\necho hi\nls -la\n",
    "scripts/leak.sh": "#!/bin/sh\ncat .secret\n",
    "scripts/sdk.py": "import boto3\nboto3.client('ec2').terminate_instances(InstanceIds=['i-1'])\n",
    "scripts/readonly.py": "import boto3\nprint(boto3.client('ec2').describe_instances())\n",
    ".secret": "TOKEN=x\n", ".env": "A=1\n", ".env.example": "A=\n",
}
PROJECT_BASH = [
    ("make infra_plan", "pass"), ("make infra_apply", "ask"), ("make deploy", "ask"), ("make release", "ask"),
    ("make", "pass"), ("make -C . infra_apply", "ask"), ("make test", "pass"), ("make launch", "ask"),
    ("bash scripts/launch.sh", "ask"), ("./scripts/nested.sh", "ask"), ("./scripts/safe.sh", "pass"),
    ("sh scripts/leak.sh", "ask"), ("python3 scripts/sdk.py", "ask"), ("python3 scripts/readonly.py", "pass"),
    ("python3 -c \"import boto3; boto3.client('ec2').terminate_instances(InstanceIds=['i'])\"", "ask"),
    ("curl --aws-sigv4 aws:amz:us-east-1:ec2 https://ec2.amazonaws.com", "ask"),
    ("cat .env", "deny"), ("grep TOKEN .secret", "deny"), ("tail -n 2 .secret", "deny"), ("cat < .env", "deny"),
    ("echo 'B=2' >> .env", "pass"), ("sed -i 's/^A=.*/A=3/' .env", "pass"), ("cat .env.example", "pass"),
    ("stat .secret", "pass"), ("git check-ignore .secret .env", "pass"), ("set -a; . ./.secret; set +a; make infra_plan", "pass"),
    ("aws secretsmanager get-secret-value --secret-id prod/db", "deny"), ("terraform output -json", "deny"),
    ("terraform output -json | jq keys", "pass"), ("printenv", "deny"), ("kubectl get secret db -o yaml", "deny"),
    ("gcloud auth print-access-token", "deny"), ("az keyvault secret show --vault-name v -n s", "deny"),
]
PROJECT_BASH += [
    ("ssh -F none dr-host1 'sudo docker compose down'", "ask"), ("ssh dr-host1 docker restart web", "ask"),
    ("docker -H ssh://dr-host1 compose up -d", "ask"), ("ssh dr-host1 docker ps", "pass"),
    ("ssh dr-host1 'docker compose logs --tail 50'", "pass"), ("docker compose down", "pass"),
    ("docker run --rm alpine echo hi", "pass"), ("docker compose up -d", "pass"),
    ("sed -i 's/ask/allow/' .claude/hooks/done-gate.py", "ask"), ("echo '{}' > .claude/settings.json", "ask"),
    ("rm .claude/hooks/done-gate.py", "ask"), ("cp /tmp/x .claude/goodbehavior/profiles/devops.md", "ask"),
    ("python3 -c \"open('.claude/settings.local.json','w').write('{}')\"", "ask"),
    ("cat .claude/settings.json", "pass"), ("echo 'TF_IN_AUTOMATION=1' >> Makefile.local", "pass"),
]
PROJECT_TOOLS = [("Edit", ".claude/settings.json", "ask"), ("Write", ".claude/hooks/done-gate.py", "ask"),
                 ("Edit", ".claude/goodbehavior/profiles/devops.md", "ask"), ("Edit", "Makefile", "pass"),
                 ("Read", ".env", "deny"), ("Read", ".secret", "deny"), ("Read", ".env.example", "pass"),
                 ("Read", "~/.aws/credentials", "deny"), ("Read", "Makefile", "pass"), ("Grep", ".secret", "deny"),
                 ("Edit", ".env", "pass"), ("Read", ".claude/settings.json", "pass")]


def run_tool(tool, tool_input, project_dir, cwd, mode="default"):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=project_dir)
    r = subprocess.run([sys.executable, HOOK], env=env, capture_output=True, text=True,
                       input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "permission_mode": mode,
                                         "tool_input": tool_input, "cwd": cwd}))
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "pass")


def main():
    failures = 0
    profile_dir = tempfile.mkdtemp()
    os.makedirs(os.path.join(profile_dir, ".claude", "goodbehavior", "profiles"))
    shutil.copy(DEVOPS, os.path.join(profile_dir, ".claude", "goodbehavior", "profiles", "devops.md"))
    cases = [c + ("",) for c in CASES] + [c + (profile_dir,) for c in DEVOPS_CASES]
    for i, (label, tools, text, want_exit, want_frag, pdir) in enumerate(cases):
        active = "stop_hook_active" in label
        code, err = run_hook(tools, text, stop_hook_active=active, project_dir=pdir)
        ok = code == want_exit and (want_frag is None or want_frag in err)
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            failures += 1
            print(f"        expected exit={want_exit} frag={want_frag!r}; got exit={code} stderr={err[:200]!r}")
    empty_dir = tempfile.mkdtemp()
    guard_cases = ([(c, profile_dir, "ask") for c in GUARD_ASK] + [(c, profile_dir, "pass") for c in GUARD_PASS]
                   + [(c, profile_dir, "ask") for c in guide_probe_commands()[1]]  # guides' pause points ask
                   + [(c, profile_dir, "pass") for c in guide_probe_commands()[0]]  # guides' read-only probes pass
                   + [("terraform apply tfplan", empty_dir, "pass")])  # no profile match: lines -> no-op
    guard_bad = []
    for command, pdir, want in guard_cases:
        code, got = run_guard(command, pdir)
        if code != 0 or got != want:
            guard_bad.append(f"{command!r}: want {want}, got {got} (exit {code})")
    print(f"  {'PASS' if not guard_bad else 'FAIL'}  guard: {len(guard_cases)} commands decided correctly")
    for b in guard_bad:
        print(f"        {b}")
    failures += bool(guard_bad)
    cases += [None]

    # done-gate hands PreToolUse to an installed profile guard (guard.py), and fails closed if it is broken
    gdir = tempfile.mkdtemp()
    os.makedirs(os.path.join(gdir, ".claude", "goodbehavior", "profiles", "devops"))
    guard_src = os.path.join(os.path.dirname(__file__), "..", "templates", "profiles", "devops", "guard.py")
    gpath = os.path.join(gdir, ".claude", "goodbehavior", "profiles", "devops", "guard.py")
    shutil.copy(guard_src, gpath)
    deleg = [run_tool("Bash", {"command": "terraform apply"}, gdir, gdir) == "ask",
             run_tool("Bash", {"command": "cat .env"}, gdir, gdir) == "deny",
             run_tool("Bash", {"command": "ls"}, gdir, gdir) == "pass"]
    with open(gpath, "w") as f:
        f.write("raise RuntimeError('broken guard')\n")
    deleg.append(run_tool("Bash", {"command": "ls"}, gdir, gdir) == "deny")
    print(f"  {'PASS' if all(deleg) else 'FAIL'}  done-gate delegates to the profile guard and fails closed if it breaks")
    failures += not all(deleg)
    cases += [None]
    shutil.rmtree(gdir, ignore_errors=True)

    project = tempfile.mkdtemp()
    for rel, body in PROJECT_FILES.items():
        os.makedirs(os.path.dirname(os.path.join(project, rel)), exist_ok=True)
        with open(os.path.join(project, rel), "w") as f:
            f.write(body)
    bad = [f"{c!r}: want {w}, got {g}" for c, w in PROJECT_BASH
           if (g := run_tool("Bash", {"command": c}, profile_dir, project)) != w]
    bad += [f"{tool} {path}: want {w}, got {g}" for tool, path, w in PROJECT_TOOLS
            if (g := run_tool(tool, {"file_path": os.path.expanduser(path) if path.startswith("~") else os.path.join(project, path)},
                              profile_dir, project)) != w]
    # with permissions bypassed an "ask" may be skipped by the harness, so it must become a deny; passes stay passes
    for tool, inp, want in [("Edit", {"file_path": os.path.join(project, ".claude/hooks/done-gate.py")}, "deny"),
                            ("Bash", {"command": "make infra_apply"}, "deny"),
                            ("Bash", {"command": "make infra_plan"}, "pass"), ("Read", {"file_path": os.path.join(project, ".env")}, "deny")]:
        got = run_tool(tool, inp, profile_dir, project, mode="bypassPermissions")
        if got != want:
            bad.append(f"bypassPermissions {tool} {inp}: want {want}, got {got}")
    print(f"  {'PASS' if not bad else 'FAIL'}  guard: make targets, scripts, inline code and secrets "
          f"({len(PROJECT_BASH) + len(PROJECT_TOOLS)} cases)")
    for b in bad:
        print(f"        {b}")
    failures += bool(bad)
    cases += [None]
    shutil.rmtree(project, ignore_errors=True)
    shutil.rmtree(profile_dir, ignore_errors=True)
    shutil.rmtree(empty_dir, ignore_errors=True)
    print(f"test_hook: {len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
