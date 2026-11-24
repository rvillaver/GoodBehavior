#!/usr/bin/env python3
"""Devops guide CLI check — every `aws`/`az`/`gcloud`/`doctl` command written in templates/profiles/devops/*.md is
run through the real CLI, offline, to prove it parses: the command exists, its flags exist, required arguments are
there, and (aws, az) the --query expression compiles.

Nothing reaches a provider or a real account. Each CLI gets fake or empty credentials and an empty config, and aws
is pointed at a dead local endpoint. A command passes when it gets past parsing and stops at the missing login or
connection. A CLI that isn't installed is skipped, not failed. Field names inside --query/--format are not checked:
only a real response could show those."""
import glob, os, re, shlex, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GUIDES = sorted(glob.glob(os.path.join(ROOT, "templates", "profiles", "devops", "*.md")))

# Written in the guides on purpose but not checkable this way (each needs a reason).
KNOWN = {
    "aws ce ...": "prose, not a command",
    "az login --identity": "only works from inside an Azure workload",
    "gcloud auth list --filter=status:ACTIVE --format=\"value(account)\"": "local command, succeeds without an account",
    "gcloud config get project": "local command, succeeds without an account",
    "doctl auth list": "local command, succeeds without a token",
    'az monitor app-insights query --app <app-insights-name> -g <rg> --analytics-query "requests | where timestamp > ago(14d) | summarize p95=percentile(duration, 95), p99=percentile(duration, 99), failed=round(100.0 * countif(success == false) / count(), 2) by bin(timestamp, 1d)"': "needs the application-insights extension; the guide says so",
}

# Placeholder values that satisfy client-side format checks (ARNs, IDs, dates).
SUBS = {
    "<role-arn>": "arn:aws:iam::123456789012:role/dummy",
    "<arn>": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/x",
    "<tg-arn>": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/x/1",
    "<acl-arn>": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/x/00000000-0000-0000-0000-000000000000",
    "<lb-arn>": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/x/1",
    "<acl-id>": "00000000-0000-0000-0000-000000000000", "<image>": "us-docker.pkg.dev/p/r/i:tag",
    "<policy-id>": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
                   "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/p",
    "<account-id>": "123456789012",
    "<30-days-ago>": "2026-01-01T00:00:00Z", "<now>": "2026-01-31T00:00:00Z", "<yyyy-mm-dd>": "2026-01-01",
    "<iso-time>": "2026-01-01T00:00:00Z", "<14-days-ago>": "2026-01-17T00:00:00Z",
    "<yyyy-mm-ddThh:mm:ssZ>": "2026-01-01T00:00:00Z", "<epoch-seconds>": "1767225600",
    "<resource-id>": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
                     "Microsoft.Compute/virtualMachines/vm",
    "<public-ip-id>": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/"
                      "Microsoft.Network/publicIPAddresses/ip",
    "<subscription-id>": "00000000-0000-0000-0000-000000000000", "<app-id>": "00000000-0000-0000-0000-000000000000",
    "<principal-id>": "00000000-0000-0000-0000-000000000000",
    "<sa-email>": "x@p.iam.gserviceaccount.com", "<billing-account-id>": "000000-000000-000000",
    "<region>": "us-central1", "<zone>": "us-central1-a", "<project>": "dummy-project",
}


def fill(cmd):
    for k, v in SUBS.items():
        cmd = cmd.replace(k, v)
    return re.sub(r"<[^>]+>", "dummy", cmd)


def before_pipe(cmd):
    """The command up to its first unquoted `|`: what follows is local text processing, not the CLI."""
    quote = None
    for i, ch in enumerate(cmd):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "|":
            return cmd[:i].strip()
    return cmd


def guide_commands(cli):
    found = []
    for g in GUIDES:
        for c in re.findall(rf"`({cli} [^`]+)`", open(g, encoding="utf-8").read()):
            c = before_pipe(c.strip())
            if cli == "aws" and "--endpoint-url" in c:  # Spaces (S3-compatible): check the S3 call itself
                c = re.sub(r" --endpoint-url \S+", "", c)
            found.append((os.path.basename(g), c))
    return list(dict.fromkeys(found))


def clean_env(drop_prefixes):
    return {k: v for k, v in os.environ.items() if not k.startswith(drop_prefixes)}


def runner(cli, tmp):
    """(argv_builder, env, pass_pattern) for each CLI, all isolated from any real login."""
    if cli == "aws":
        env = clean_env(("AWS_",))
        env.update(AWS_ACCESS_KEY_ID="fake", AWS_SECRET_ACCESS_KEY="fake", AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                   AWS_CONFIG_FILE=os.devnull, AWS_EC2_METADATA_DISABLED="true", AWS_DEFAULT_REGION="us-east-1",
                   AWS_MAX_ATTEMPTS="1")
        argv = lambda c: shlex.split(fill(c)) + ["--endpoint-url", "http://127.0.0.1:9",
                                                 "--cli-connect-timeout", "1", "--cli-read-timeout", "1"]
        return argv, env, r"Could not connect to the endpoint URL"
    if cli == "az":
        env = clean_env(("AZURE_", "ARM_"))
        env.update(AZURE_CONFIG_DIR=os.path.join(tmp, "az"), AZURE_EXTENSION_USE_DYNAMIC_INSTALL="no",
                   AZURE_CORE_COLLECT_TELEMETRY="no")
        return (lambda c: shlex.split(fill(c))), env, r"az login"
    if cli == "gcloud":
        env = clean_env(("CLOUDSDK_", "GOOGLE_"))
        env.update(CLOUDSDK_CONFIG=os.path.join(tmp, "gcloud"), CLOUDSDK_CORE_DISABLE_PROMPTS="1",
                   CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK="1")
        return (lambda c: shlex.split(fill(c))), env, \
            r"(do not currently have an active account|gcloud auth login|Failed to find attribute \[project\]" \
            r"|required property \[project\])"
    if cli == "doctl":
        cfg = os.path.join(tmp, "doctl.yaml")
        open(cfg, "w").close()
        env = clean_env(("DIGITALOCEAN",))
        return (lambda c: ["doctl", "--config", cfg] + shlex.split(fill(c))[1:]), env, r"access token is required"
    raise ValueError(cli)


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for cli in ("aws", "az", "gcloud", "doctl"):
            cmds = [(g, c) for g, c in guide_commands(cli) if c not in KNOWN]
            if not shutil.which(cli):
                print(f"  SKIP  {cli}: not installed ({len(cmds)} commands unchecked)")
                continue
            argv, env, ok_pattern = runner(cli, tmp)

            def check(item):
                g, c = item
                try:
                    r = subprocess.run(argv(c), capture_output=True, text=True, env=env, timeout=180)
                except subprocess.TimeoutExpired:
                    return g, c, False, "timed out"
                out = (r.stderr + r.stdout).strip()
                return g, c, re.search(ok_pattern, out) is not None, out

            results = list(ThreadPoolExecutor(8).map(check, cmds))
            bad = [(g, c, out) for g, c, ok, out in results if not ok]
            print(f"  {'PASS' if not bad else 'FAIL'}  {cli}: {len(results) - len(bad)}/{len(results)} guide commands parse")
            for g, c, out in bad:
                print(f"        {g}: {c[:100]}\n          -> {' | '.join(out.splitlines()[:2])[:200]}")
                failures.append(f"{cli}: {c[:60]}")
    print(f"test_guide_cli: {'FAILED: ' + '; '.join(failures) if failures else 'all passed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
