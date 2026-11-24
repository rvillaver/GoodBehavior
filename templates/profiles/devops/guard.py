#!/usr/bin/env python3
"""GoodBehavior devops guard — PreToolUse. Local work runs; infrastructure and remote changes ask; secrets never show.

Adapted from a hand-built, default-deny guard (write-guard v2) that an owner wrote after an AI ran
`terraform apply` and `aws mgn start-replication` unasked. It keeps that guard's parser, but not its default:
like a developer's machine, local work runs, and only what reaches past the project asks.

  run    local work: reads, edits and deletes inside the project or temp folders, local git (commit, rm,
         rebase), tests, linters, builds, scratch scripts, unknown local programs, cloud reads, plans, tunnels.
         A tool with no checker of its own is judged by shape: its action words (list/get vs delete/deploy)
         and whether it reaches a remote (guard-tools.txt, a credential variable or .env key, a config in HOME).
         Commands are still read part by part: quotes, variables, $(...), heredocs, pipes, `make` recipes,
         scripts and the scripts they source, Python (its subprocess calls too), node tests, bats files,
         docker images that wrap a cloud CLI, and ssh remote commands.
  ask    it changes infrastructure or a remote service (cloud/kubectl/helm/terraform writes, databases,
         git push, ssh changes, CI runs with secrets), deletes outside the project, throws away uncommitted
         work, installs software, stops processes, runs code the guard can't read (eval, perl -e system,
         npx), or edits the guard and its settings. The user is asked right away, with what was found and why.
  deny   it would put a secret in the conversation (credential files, secret-manager reads, token
         printers, state dumps), or the guard itself failed (fail closed), or permissions are bypassed and
         the decision would have been "ask" (Claude Code was seen skipping a hook's "ask" in that mode).

Every ask and deny is appended to .claude/goodbehavior/guard.log.

It is a speed bump, not a sandbox: a shell is a programming language and no parser closes every route.
The hard boundary is the credential the session runs with; which profile that is stays the user's call.
"""
import ast
import fnmatch
import glob
import json
import os
import re
import shlex
import sys
import tempfile
import time

HOME = os.path.expanduser("~")
MAX_DEPTH = 4
MAX_FILE_BYTES = 300_000

# --------------------------------------------------------------------------------------------------------------
# Decisions. A hit is (what, why, level); "deny" (secret) beats "user" (only the user may run it) beats "ask".
# --------------------------------------------------------------------------------------------------------------


def ask(what, why):
    return (what, why, "ask")


def secret(what, why):
    return (what, why, "deny")


def user_only(what, why):
    return (what, why, "user")


LEVEL_RANK = {"ask": 1, "user": 2, "deny": 3}
USE_SECRET = ("reads a secret file to use the value (for example as an API token), not to show it. If the user "
              "says yes, keep the value out of the output: no echo or print of it, no `curl -v`, no `set -x`. "
              "Loading it with `set -a; . ./.env; set +a` and using `$NAME` runs without asking")


def as_use(h, cwd):
    """A project secret file (`.env*`, `.secret`) read inside a `$(...)` hands the value to the command, not the
    screen: the user may allow it. Reading one straight to the screen (`cat .env`) and cloud credential stores stay
    denied."""
    m = h and h[2] == "deny" and h[1] == "prints a secret file" and re.search(r"reading `([^`]+)`", h[0])
    if m and is_project_secret(m.group(1), cwd):
        return ask(h[0], USE_SECRET)
    if h and h[2] == "deny" and h[1] in {"returns a credential or secret", "prints secret values", "prints a secret"}:
        return ask(h[0], "fetches a secret from a secret manager or token command to use it, not to show it. If "
                   "the user says yes, keep the value out of the output: no echo or print of it, no `curl -v`, "
                   "no `set -x`")
    return h


def worse(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return b if LEVEL_RANK[b[2]] > LEVEL_RANK[a[2]] else a


# --------------------------------------------------------------------------------------------------------------
# Paths. Protected: writing them changes the guard or what an allowed command does (ask). Secret: reading them
# shows a credential (deny).
# --------------------------------------------------------------------------------------------------------------
PROTECTED_PARTS = (  # .claude/ only where a write can switch the guard off or change what runs; memory stays writable
    "/.claude/settings", "/.claude/hooks/", "/.claude/goodbehavior/", "/.claude/plugins/", "/.mcp.json", "/.claude.json", "/.git/config", "/.git/hooks/", "/.git/info/",
    "/.ssh/", "/.aws/", "/.azure/", "/.config/gcloud/", "/.config/doctl/", "/.kube/", "/.docker/",
    "/.terraform.d/", "/.terraformrc", "/.config/git/", "/.config/gh/", "site-packages/", "dist-packages/",
    "/Library/LaunchAgents/", "/Library/LaunchDaemons/", "/etc/", "/.terraform/",
)
PROTECTED_BASENAMES = {
    ".gitconfig", ".netrc", ".curlrc", ".wgetrc", ".npmrc", ".pypirc", ".zshrc", ".zshenv", ".zprofile",
    ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".inputrc", ".envrc",
    "sitecustomize.py", "usercustomize.py", ".terraform.lock.hcl", ".checkov.yaml", ".checkov.yml",
    "trivy.yaml", ".trivyignore", ".trivyignore.yaml", ".tflint.hcl",
}
SECRET_PARTS = (
    "/.aws/credentials", "/.aws/sso/", "/.aws/cli/cache", "/.aws/login", "/.ssh/id_", "/.docker/config.json",
    "/.config/gcloud/credentials.db", "/.config/gcloud/access_tokens.db", "/.config/gcloud/legacy_credentials",
    "/.config/gcloud/application_default_credentials.json", "/.azure/msal_token_cache",
    "/.azure/accessTokens", "/.azure/service_principal_entries", "/.config/doctl/config.yaml", "/.kube/config",
    "/.config/gh/hosts", "/.terraform.d/credentials", "/.secret/", "/.secrets/", "/.kubeconfig/",
)
SECRET_BASENAMES = {".secret", ".secrets", ".netrc", ".pgpass", ".git-credentials", ".npmrc", ".pypirc",
                    ".envrc", "credentials.json", "service-account.json", "environ", "kubeconfig"}
SECRET_PATTERNS = re.compile(r"^(\.env(\.(?!example$|sample$|template$|dist$)[^/]+)?|.*\.tfstate(\.backup)?|"
                             r".*\.(pem|key|p12|pfx|jks|keystore)|id_(rsa|dsa|ecdsa|ed25519)|.*\.secret|"
                             r"\.?kubeconfig|[\w.-]*kubeconfig[\w.-]*\.(ya?ml|json|conf))$")


def project_dir(payload):
    return os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()


def resolve(path, cwd):
    """Absolute, symlink-resolved path, or None when it can't be known (a variable or substitution in it)."""
    p = path.replace("${HOME}", HOME).replace("$HOME", HOME).replace("${PWD}", cwd).replace("$PWD", cwd)
    if p.startswith("~"):
        p = os.path.expanduser(p)
    if "$" in p or "`" in p or "__SUBST__" in p:
        return None
    return os.path.realpath(os.path.join(cwd, p))


def path_dirs():
    dirs = set()
    for d in os.environ.get("PATH", "").split(os.pathsep) + ["/usr/local/bin", "/opt/homebrew/bin"]:
        if d:
            dirs.add(os.path.realpath(d))
    return dirs


def loop_values(path):
    """Every value of `path` when its only variables are `for NAME in a b c` loop variables, else None."""
    names = set(re.findall(r"\$\{?([A-Za-z_]\w*)\}?", path))
    if not names or "`" in path or "__SUBST__" in path or re.search(r"\$[^{A-Za-z_]|\$\{[^}]*[^\w}]", path) \
            or any(n not in LOOPS for n in names):
        return None
    out = [path]
    for n in names:
        out = [re.sub(r"\$\{%s\}|\$%s(?!\w)" % (n, n), lambda _m, v=v: v, o) for o in out for v in LOOPS[n]]
    return out


def is_protected(path, cwd):
    real = resolve(path, cwd)
    values = loop_values(path) if real is None else None
    if values is not None:
        return any(is_protected(v, cwd) for v in values)
    if real is None and TEST_MODE:  # tests write into their own temp folders, named by variables
        return bool(re.search(r"\.claude|\.mcp\.json|\.ssh|\.aws|\.kube|\.git/|\.terraform|HOME|~", path))
    if real is None:
        # `$DIR/$name.log`: a known, unprotected folder plus an unknown file name (no further /) is fine
        cut = min([i for i in (path.find("$"), path.find("`"), path.find("__SUBST__")) if i >= 0] or [len(path)])
        prefix, rest = path[:cut], path[cut:]
        if "/" in prefix and "/" not in rest:
            folder = os.path.dirname(prefix.rstrip("/") + "/x")
            if resolve(folder, cwd) is None:
                return True
            return is_protected(folder, cwd) or os.path.basename(folder) == ".claude"
        return True
    for c in (real, os.path.abspath(os.path.join(cwd, os.path.expanduser(path)))):
        if any(m in c + "/" for m in PROTECTED_PARTS) or c.endswith("/.claude"):
            return True
        if "/.claude/projects/" in c and c.endswith(".jsonl"):
            return True  # session transcripts hold the user's answers, which grant consent
        if os.path.basename(c) in PROTECTED_BASENAMES:
            return True
        if os.path.dirname(c) in path_dirs():
            return True
    return False


def is_project_secret(path, cwd):
    """The project's own token files, which code may read to use (never to show) after the user's yes."""
    real = resolve(path, cwd) or path
    return is_secret(path, cwd) and (bool(re.match(r"^\.env(\.[^/]+)?$", os.path.basename(real)))
                                     or os.path.basename(real) in {".secret", ".secrets"}
                                     or "/.secret/" in real or "/.secrets/" in real)


def is_secret(path, cwd):
    cleaned = re.sub(r"\$\{\w+\}", "$V", path or "")
    if not path or path.startswith("-") or re.search(r"\s|[|(){}\[\]\"]", cleaned):
        return False  # not a path: a filter, a message, an expression
    if any(ch in path for ch in "*?["):
        base = resolve(path, cwd)
        matches = glob.glob(base) if base else []
        return any(is_secret(m, cwd) for m in matches) or bool(SECRET_PATTERNS.match(os.path.basename(path)))
    real = resolve(path, cwd) or path
    for c in (path, real):
        if any(m in c for m in SECRET_PARTS):
            return True
        b = os.path.basename(c.rstrip("/"))
        if b in SECRET_BASENAMES or SECRET_PATTERNS.match(b):
            return True
    return False


SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}


def secrets_under(directory, excludes=(), hidden=True, follow_links=False, limit=20_000, exclude_dirs=()):
    """Secret files a recursive search of `directory` would read, minus `--exclude` globs and `--exclude-dir`
    folders. Symlinks inside the folder are skipped unless the tool follows them (grep -R, rg -L)."""
    found, seen = [], 0
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and (hidden or not d.startswith("."))
                       and not any(fnmatch.fnmatch(d, e.rstrip("/")) for e in exclude_dirs)]
        for f in filenames:
            seen += 1
            if seen > limit:
                return found
            if not hidden and f.startswith("."):
                continue
            p = os.path.join(dirpath, f)
            if os.path.islink(p) and not follow_links:
                continue
            if is_secret(p, directory) and not any(fnmatch.fnmatch(f, e) for e in excludes):
                found.append(os.path.relpath(p, directory))
    return found


# --------------------------------------------------------------------------------------------------------------
# Environment variables. Picking an account or region is the user's call and runs; variables that change which
# program runs, or how, ask.
# --------------------------------------------------------------------------------------------------------------
DANGEROUS_ENV = re.compile(
    r"^(PATH|HOME|SHELL|ENV|BASH_ENV|ZDOTDIR|IFS|PS4|PROMPT_COMMAND|CDPATH|FPATH|EDITOR|VISUAL|PAGER|TMPDIR|"
    r"LD_\w+|DYLD_\w+|PYTHON(PATH|STARTUP|HOME|USERBASE)|NODE_OPTIONS|NODE_PATH|PERL5\w*|RUBY\w*|GIT_\w+|"
    r"SSH_\w+|TF_CLI_\w+|TF_PLUGIN_\w+|TF_CLI_CONFIG_FILE|MAKE\w*|LESS\w*|CURL_\w+|WGETRC|DOCKER_HOST|"
    r"DOCKER_CONFIG|AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|CLOUDSDK_CONFIG|AZURE_CONFIG_DIR)$")
SECRET_ENV = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API_?KEY|ACCESS_KEY|SESSION_KEY)",
                        re.I)
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$", re.S)


def env_problem(name):
    if DANGEROUS_ENV.match(name) and not TEST_MODE:
        return ask("`%s=…`" % name, "changes which program runs or how it behaves")
    return None


# --------------------------------------------------------------------------------------------------------------
# Cloud CLIs: read operations run; reads that hand back a credential are denied; everything else asks.
# --------------------------------------------------------------------------------------------------------------
READ_PREFIXES = ("describe", "get", "list", "ls", "head", "search", "lookup", "select", "query", "scan", "batch-get",
                 "check", "simulate", "estimate", "preview", "validate", "wait", "tail", "filter", "help",
                 "generate-cli-skeleton", "view", "summarize", "count", "resolve", "show", "read")
AWS_SECRET_OPS = {
    ("secretsmanager", "get-secret-value"), ("secretsmanager", "batch-get-secret-value"),
    ("ssm", "get-parameter"), ("ssm", "get-parameters"), ("ssm", "get-parameters-by-path"),
    ("ec2", "get-password-data"), ("ecr", "get-login-password"), ("ecr", "get-authorization-token"),
    ("ecr-public", "get-login-password"), ("codeartifact", "get-authorization-token"),
    ("sts", "get-session-token"), ("sts", "get-federation-token"), ("sso", "get-role-credentials"),
    ("eks", "get-token"), ("redshift", "get-cluster-credentials"), ("rds", "generate-db-auth-token"),
    ("lightsail", "get-instance-access-details"), ("cognito-identity", "get-credentials-for-identity"),
    ("kms", "decrypt"), ("iam", "create-access-key"), ("lambda", "get-function-configuration"),
}
AWS_SECRET_UNLESS_NO_DECRYPT = {("ssm", "get-parameter"), ("ssm", "get-parameters"),
                                ("ssm", "get-parameters-by-path")}
AWS_GLOBAL_VALUE_FLAGS = {"--profile", "--region", "--output", "--query", "--endpoint-url", "--color",
                          "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format"}
SSM_TUNNEL_DOCS = {"AWS-StartPortForwardingSession", "AWS-StartPortForwardingSessionToRemoteHost",
                   "AWS-StartPortForwardingSessionToSocket"}


def positional(args, value_flags=()):
    words, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if "=" not in a and a in value_flags:
                skip = True
            continue
        words.append(a)
    return words


def flag_value(args, *names):
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                return args[i + 1]
            if a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


# Read-only subcommands of backup and hypervisor tools (anything else asks).
TOOL_READS = {
    "restic": {"snapshots", "check", "ls", "stats", "find", "diff", "version"},
    "borg": {"list", "info", "check", "diff", "version"},
    "qm": {"list", "listsnapshot", "config", "status", "pending"},
    "pct": {"list", "listsnapshot", "config", "status", "pending"},
}
GOVC_READ = re.compile(r"^(about|ls|find|tree|events|.*\.(info|ls|tree|sample|list|ip|summary))$")

# Monitoring CLIs: first verb -> None (every subcommand reads or checks local files) or the read-only second verbs
# (the first verb alone reads too). Anything else asks: a test alert pages people, a silence mutes them, a rules
# or config sync changes what alerts, a push writes metrics.
OBS_READS = {
    "amtool": {"check-config": None, "config": None, "cluster": None, "template": None, "alert": {"query"},
               "silence": {"query"}},
    "promtool": {"check": None, "test": None, "query": None, "debug": None, "tsdb": None, "promql": None},
    "logcli": {"query": None, "instant-query": None, "labels": None, "series": None, "stats": None, "volume": None,
               "volume_range": None, "detected-fields": None},
    "mimirtool": {"rules": {"lint", "check", "prepare", "list", "print", "get", "diff"},
                  "alertmanager": {"get", "verify"}, "analyze": None, "config": None, "acl": None},
    "cortextool": {"rules": {"lint", "check", "prepare", "list", "print", "get", "diff"},
                   "alertmanager": {"get", "verify"}, "analyse": None},
    "lokitool": {"rules": {"lint", "check", "prepare", "list", "print", "get", "diff"}},
    "grafana-cli": {"plugins": {"ls", "list-remote", "list-versions"}},
    "grafanactl": {"resources": {"get", "list", "pull", "validate"}, "config": None},
}
OBS_VALUE_FLAGS = {"--alertmanager.url", "-o", "--output", "--config.file", "--addr", "--org-id", "--since",
                   "--from", "--to", "--limit", "--address", "--id", "--key", "--user", "--config", "--context",
                   "--author", "-a", "--comment", "-c", "--duration", "-d", "--annotation", "--start", "--end",
                   "--pluginsDir", "--homepath"}
OBS_WHY = {("amtool", "alert"): "fires an alert, which can page or notify people",
           ("amtool", "silence"): "adds, changes or expires a silence, which mutes or unmutes alerts"}


# Load generators: Claude never runs them, even with a yes. It hands the user the script and command instead.
LOAD_TOOLS = {"k6", "hey", "ab", "wrk", "wrk2", "vegeta", "locust", "artillery", "jmeter", "siege", "oha",
              "bombardier", "autocannon", "gatling", "gatling.sh", "drill", "ddosify", "plow"}


def check_obs(name, args):
    words = positional(args, OBS_VALUE_FLAGS)
    if name == "grafana":  # the server binary: `grafana cli ...` is grafana-cli, `grafana server` runs locally
        if words[:1] != ["cli"]:
            return None
        name, words = "grafana-cli", words[1:]
    if not words or "--help" in args or "-h" in args or words[0] in {"help", "version", "--version"}:
        return None
    reads = OBS_READS[name].get(words[0], False)
    if reads is None or (reads and (len(words) == 1 or words[1] in reads)):
        return None
    return ask("`%s %s`" % (name, " ".join(words[:2])),
               OBS_WHY.get((name, words[0]), "changes alerting, rules or a monitoring server"))


def check_aws(args):
    words = positional(args, AWS_GLOBAL_VALUE_FLAGS)
    if not words or words[0] == "help" or (len(words) >= 2 and words[1] == "help") or "--version" in args:
        return None
    if words[0] == "configure":
        if len(words) == 2 and words[1] in {"list", "list-profiles"}:
            return None
        return secret("`aws configure %s`" % " ".join(words[1:2]), "reads or writes credentials")
    if len(words) < 2:
        return ask("`aws %s`" % words[0], "is not a known read-only AWS operation")
    service, op = words[0], words[1]
    if service == "ssm" and op == "start-session":
        doc = flag_value(args, "--document-name")
        if sum(a == "--document-name" or a.startswith("--document-name=") for a in args) == 1 and doc in SSM_TUNNEL_DOCS:
            return None  # a port-forward tunnel: opens a local port, runs nothing on the host
        return ask("`aws ssm start-session`", "opens a shell on the instance, where commands can't be checked")
    if (service, op) in AWS_SECRET_OPS:
        if (service, op) in AWS_SECRET_UNLESS_NO_DECRYPT and "--with-decryption" not in args:
            return None
        return secret("`aws %s %s`" % (service, op), "returns a credential or secret")
    if service == "s3" and op == "presign":
        return secret("`aws s3 presign`", "mints a credentialed URL")
    if service == "s3" and op in {"ls"}:
        return None
    if service == "logs" and op in {"start-query", "stop-query", "start-live-tail"}:
        return None  # Logs Insights queries and live tail only read log events
    if (op.startswith(READ_PREFIXES) or op in {"test-connection"}) and op not in {"get-console-screenshot"}:
        return None
    return ask("`aws %s %s`" % (service, op), "changes something in the AWS account")


AZ_SECRET = re.compile(r"\b(keyvault (secret (show|download)|key download|certificate download)|account "
                       r"get-access-token|storage account (keys list|show-connection-string)|acr credential "
                       r"show|webapp deployment list-publishing-(credentials|profiles)|cosmosdb keys list)\b|"
                       r"\blist-(keys|credentials|connection-strings|secrets)\b|\bshow-connection-string\b")
AZ_READ = {"list", "show", "get", "exists", "query", "describe", "list-locations", "list-skus", "list-usage",
           "check-name", "version", "help"}


def check_az(args):
    # az takes no positional values: the command path is every word before the first flag, so query strings and
    # flag values (`--offset 7d`, `--metric "Percentage CPU"`) are never mistaken for the verb
    words = []
    for a in args:
        if a.startswith("-"):
            break
        words.append(a)
    if not words or "--version" in args or "--help" in args or "-h" in args:
        return None
    joined = " ".join(words)
    if AZ_SECRET.search(joined):
        return secret("`az %s`" % joined, "returns a credential or secret")
    if words[0] == "account" and words[1:2] and words[1] in {"show", "list", "set", "list-locations"}:
        return None
    if words[0] == "rest":
        method = (flag_value(args, "--method", "-m") or "get").lower()
        return None if method in {"get", "head"} else ask("`az rest --method %s`" % method, "writes through the API")
    if words[0] == "graph" and words[1:2] == ["query"]:
        return None
    verb = words[-1]
    if verb in AZ_READ or verb.startswith(("list-", "show-", "get-")):
        return None
    return ask("`az %s`" % joined, "changes something in the Azure subscription")


GCLOUD_SECRET = re.compile(r"\b(secrets versions access|auth (print-access-token|print-identity-token|"
                           r"application-default print-access-token)|iam service-accounts keys create|"
                           r"sql generate-login-token)\b")
GCLOUD_READ = {"list", "describe", "get-iam-policy", "get", "read", "print-settings", "get-value", "info",
               "version", "help", "lookup", "search-all-resources", "search-all-iam-policies", "analyze-iam-policy",
               "troubleshoot", "list-configs", "list-tags", "get-ancestors"}


def check_gcloud(args):
    words = positional(args, {"--project", "--format", "--filter", "--zone", "--region", "--location",
                              "--account", "--impersonate-service-account"})
    if not words or "--help" in args or "--version" in args:
        return None
    joined = " ".join(words)
    if GCLOUD_SECRET.search(joined):
        return secret("`gcloud %s`" % joined, "returns a credential or secret")
    if words[0] == "config" and words[1:2] and words[1] in {"get", "list", "get-value", "set", "configurations"}:
        return None
    if words[0] == "auth" and words[1:2] == ["list"]:
        return None
    if words[0] == "policy-troubleshoot" or words[:2] == ["storage", "ls"]:
        return None  # explains an IAM decision; lists object names
    if words[-1] == "ssh" or "ssh" in words[:3]:
        return ask("`gcloud %s`" % joined, "opens a shell or runs a command on the host")
    if any(w in GCLOUD_READ for w in words) and not any(w in {"set-iam-policy", "add-iam-policy-binding"} for w in words):
        return None
    return ask("`gcloud %s`" % joined, "changes something in the Google Cloud project")


DOCTL_SECRET = re.compile(r"\b(auth token|kubernetes cluster kubeconfig show|databases (connection|user get)|"
                          r"registry docker-config|registry login)\b")
DOCTL_READ = {"list", "ls", "get", "show", "logs", "help", "version", "summary", "search", "list-v2", "list-tags",
              "list-manifests", "subscription-tiers", "available-regions", "get-active", "backups"}
DOCTL_WRITE = {"create", "delete", "rm", "update", "apply", "tag", "untag", "rebuild", "resize", "power-on",
               "power-off", "power-cycle", "reboot", "shutdown", "fork", "restore", "migrate", "attach", "detach",
               "assign", "unassign", "reset", "upgrade", "add", "remove", "set", "save", "init", "switch"}


def check_doctl(args):
    words = positional(args, {"--format", "-o", "--output", "--context", "-t", "--access-token", "--config", "-c"})
    if not words or "--help" in args or words[0] == "version":
        return None
    joined = " ".join(words)
    if DOCTL_SECRET.search(joined):
        return secret("`doctl %s`" % joined, "returns a credential or secret")
    if words[:1] == ["secrets"] and words[1:2] in (["get"], ["g"]) and (
            any(a.split("=", 1)[0] in {"--show", "--kvs", "--raw", "--key"} for a in args)
            or (flag_value(args, "-o", "--output") or "").lower() == "json"):
        # values are masked by default; these flags reveal them (JSON output not confirmed masked, so denied too)
        return secret("`doctl secrets get` with a reveal flag", "prints secret values")
    if any(w in DOCTL_WRITE for w in words):
        return ask("`doctl %s`" % joined, "changes something in the DigitalOcean account")
    if any(w in DOCTL_READ for w in words) or words[:1] == ["account"] or words[:1] == ["balance"]:
        return None
    return ask("`doctl %s`" % joined, "is not a known read-only DigitalOcean command")


KUBECTL_READ = {"get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "version",
                "cluster-info", "events", "diff", "wait", "port-forward"}
KUBECTL_VALUE_FLAGS = {"-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-l", "--selector",
                       "-o", "--output", "-c", "--container", "--since", "--tail", "-f", "--filename"}


def check_kubectl(args):
    words = positional(args, KUBECTL_VALUE_FLAGS)
    if not words:
        return None
    verb = words[0]
    if any(re.fullmatch(r"--dry-run(=(server|client))?", a) for a in args):
        return None  # validated and admitted by the server (or client), stored nowhere
    out = flag_value(args, "-o", "--output") or next((a[2:] for a in args if a.startswith("-o") and len(a) > 2), "")
    if verb == "get" and any(w in {"secret", "secrets"} or w.startswith("secret/") for w in words[1:]) \
            and re.match(r"(yaml|json|jsonpath|go-template|custom-columns)", out or "") \
            and not (out.startswith("custom-columns=") and not re.search(r"\.(data|stringData|annotations|managedFields)\b|\[(?!\d+\])|\*|\.\.", out)):
        # custom-columns naming only metadata or type fields (no .data, no wildcards) shows names, not values
        return secret("`kubectl get secret -o %s`" % out, "prints secret values")
    if verb == "config":
        sub = words[1] if len(words) > 1 else ""
        if sub == "view" and ("--raw" in args or "--flatten" in args):
            return secret("`kubectl config view --raw`", "prints cluster credentials")
        if sub in {"view", "get-contexts", "current-context", "get-clusters", "get-users"}:
            return None
        return ask("`kubectl config %s`" % sub, "changes the kube config")
    if verb == "auth" and words[1:2] in (["can-i"], ["whoami"]):
        return None
    if verb == "logs" and ("-f" in args or "--follow" in args):
        return ask("`kubectl logs -f`", "never returns")
    if verb in KUBECTL_READ:
        return None
    if verb == "exec" and "--" in args:
        inner = args[args.index("--") + 1:]
        if bundled(args, {"-i", "--stdin"}) and not inner[1:]:
            return ask("`kubectl exec -i`", "runs a script from stdin the guard can't see")
        if inner[:1] and inner[0].rsplit("/", 1)[-1] in SHELL_BINARIES and inner[1:2] == ["-c"] and len(inner) == 3:
            h = check_remote(inner[2])
        else:
            h = check_remote(" ".join(shlex.quote(w) for w in inner)) if inner else ask("`kubectl exec`", "has no command")
        if h is None:
            return None  # only reads inside the pod
        return (h[0].replace("remote", "in-pod"), h[1], h[2])
    return ask("`kubectl %s`" % verb, "changes something in the cluster")


HELM_READ = {"list", "ls", "status", "history", "show", "template", "lint", "search", "version", "env",
             "dependency", "verify", "diff", "pull"}  # diff renders and compares; pull downloads a chart locally


def check_helm(args):
    words = positional(args, {"-n", "--namespace", "--kube-context", "--kubeconfig", "-o", "--output", "-f",
                              "--values", "--version", "--set", "--repo"})
    if not words:
        return None
    if words[0] in {"repo", "plugin"} and words[1:2] in (["list"], ["ls"]):
        return None
    if words[0] == "get":
        return ask("`helm get`", "can print release values and manifests that hold secrets")
    if words[0] in {"install", "upgrade", "uninstall", "rollback"} and any(
            re.fullmatch(r"--dry-run(=(server|client|true))?", a) for a in args):
        return None
    if words[0] in HELM_READ:
        return None
    if words[0] == "unittest":  # the helm-unittest plugin renders charts locally; -u rewrites snapshot files
        return ask("`helm unittest --update-snapshot`", "rewrites the chart's test snapshots") \
            if bundled(args, {"-u", "--update-snapshot"}) else None
    return ask("`helm %s`" % words[0], "changes something in the cluster")


# --------------------------------------------------------------------------------------------------------------
# Terraform / OpenTofu: plan, test and friends run while the code has no escape hatch that runs local programs
# and every test mocks the providers it touches; outputs that print secrets are denied.
# --------------------------------------------------------------------------------------------------------------
TF_READ = {"plan", "test", "validate", "fmt", "output", "show", "graph", "version", "init", "get", "metadata",
           "providers", "modules"}
TF_REMOTE_MODULE = re.compile(r'module\s+"[^"]+"\s*\{[^}]*?\bsource\s*=\s*"(?!\.{1,2}/)([^"]+)"', re.S)
TF_ESCAPES = re.compile(r'data\s+"external"|provisioner\s+"(local-exec|remote-exec|file)"|provider\s+"external"')
LOCAL_PROVIDERS = {"terraform", "random", "null", "time", "local", "tls", "archive", "http", "external"}


def repo_root(cwd):
    d = cwd
    while d and d != "/":
        if os.path.isdir(os.path.join(d, ".git")):
            return d
        d = os.path.dirname(d)
    return cwd


def iac_problem(workdir):
    workdir = repo_root(workdir)  # a root module loads modules from elsewhere in the repo
    for dirpath, dirnames, filenames in os.walk(workdir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if not f.endswith((".tf", ".tftest.hcl", ".tf.json")):
                continue
            path = os.path.join(dirpath, f)
            text = read_text(path) or ""
            rel = os.path.relpath(path, workdir)
            if TF_ESCAPES.search(text):
                return ask("`terraform` here", "%s runs local programs (external data or a provisioner)" % rel)
            remote = TF_REMOTE_MODULE.search(text)
            if remote and not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+", remote.group(1)):
                return ask("`terraform` here", "%s loads module code from `%s`, which the guard can't read"
                           % (rel, remote.group(1)))
            if f.endswith(".tftest.hcl") and re.search(r'^\s*provider\s+"', text, re.M):
                return ask("`terraform test`", "%s configures a real provider, so the test would reach it" % rel)
            if f.endswith(".tftest.hcl"):
                if re.search(r"^\s*command\s*=\s*apply", text, re.M) or not re.search(r"command\s*=", text):
                    module = os.path.dirname(dirpath) if os.path.basename(dirpath) == "tests" else dirpath
                    used = "".join(read_text(os.path.join(module, g)) or "" for g in os.listdir(module)
                                   if g.endswith(".tf"))
                    providers = {m.split("_", 1)[0] for m in re.findall(r'(?:resource|data)\s+"([a-z0-9]+_[a-z0-9_]+)"', used)}
                    for p in sorted(providers - LOCAL_PROVIDERS):
                        if 'mock_provider "%s"' % p not in text:
                            return ask("`terraform test`", "%s applies without mocking the %s provider, so it "
                                       "would create and destroy real resources" % (rel, p))
    return None


# `terraform show -json` holds every attribute value in clear, secrets included. A jq filter runs when it can only
# print plan metadata: addresses, actions, key names, and the sensitive/unknown masks (booleans). `before`, `after`
# and other value trees may be read only where nothing of them is printed: inside select(), or through keys,
# length or type. Anything the check doesn't understand counts as printing values.
TF_JSON_CONTAINERS = {"resource_changes", "change"}
TF_JSON_LEAVES = {"address", "module_address", "previous_address", "mode", "type", "name", "index", "provider_name",
                  "deposed", "actions", "action_reason", "replace_paths", "importing", "format_version",
                  "terraform_version", "applyable", "complete", "errored", "key", "value"}
TF_JSON_MASKS = {"after_sensitive", "before_sensitive", "after_unknown", "before_unknown"}
JQ_WORDS = {"select", "if", "then", "else", "elif", "end", "empty", "not", "and", "or", "as", "null", "true",
            "false", "K", "M", "map", "keys", "keys_unsorted", "length", "type", "any", "all", "has", "in", "test",
            "startswith", "endswith", "contains", "inside", "join", "ascii_downcase", "ascii_upcase", "tsv", "csv"}
JQ_PATH = re.compile(r"(\$\w+|(?<![\w\])}?\"])\.)((?:\w+)?(?:\??(?:\.\w+|\[[^\[\]]*\]))*\??)")


def jq_strings(f):
    """Replace each string literal with its interpolations, `(expr), (expr)`, or with `null` when it has none."""
    out, i = [], 0
    while i < len(f):
        if f[i] != '"':
            out.append(f[i])
            i += 1
            continue
        i, parts = i + 1, []
        while i < len(f) and f[i] != '"':
            if f[i:i + 2] == "\\(":
                depth, j = 1, i + 2
                while j < len(f) and depth:
                    depth += {"(": 1, ")": -1}.get(f[j], 0)
                    j += 1
                parts.append("(" + jq_strings(f[i + 2:j - 1]) + ")")
                i = j
            else:
                i += 2 if f[i] == "\\" else 1
        out.append(" " + (", ".join(parts) or "null") + " ")
        i += 1
    return "".join(out)


def jq_prints_values(cmd):
    """None when the jq command after `terraform show -json` prints only plan metadata, else why it may not."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        return "its jq command could not be parsed"
    safe_vars, filt, k = {"__safe"}, None, 0
    while k < len(toks) and toks[k] not in {"|", ";", "&&", "||", ")", "&"}:
        t = toks[k]
        if t in {"--arg", "--argjson"} and k + 2 < len(toks):
            safe_vars.add(toks[k + 1])
            k += 3
            continue
        if t in {"-f", "--from-file", "--slurpfile", "--rawfile", "--args", "--jsonargs"} or t.startswith("-L"):
            return "jq reads its filter or data from elsewhere"
        if not t.startswith("-") and filt is None:
            filt = t
        k += 1
    if filt is None:
        return "jq with no filter prints everything"
    f = re.sub(r'\[\s*"(\w+)"\s*\]|\.\s*"(\w+)"', lambda m: "." + (m.group(1) or m.group(2)), filt)
    f = jq_strings(f)
    if ".." in f or "|=" in f or re.search(r"@(?!tsv\b|csv\b)\w+", f):
        return "the filter uses `..`, an update or a format that can print whole values"
    side = re.search(r"\b(error|debug|stderr|halt_error|input_line_number)\b", f)
    if side:  # these print to stderr even inside select()
        return "the filter calls `%s`, which prints what it is given" % side.group(1)
    while True:  # select() only filters, so what it reads is never printed
        m = re.search(r"\bselect\s*\((?!S\))", f)
        if not m:
            break
        depth, j = 1, m.end()
        while j < len(f) and depth:
            depth += {"(": 1, ")": -1}.get(f[j], 0)
            j += 1
        f = f[:m.start()] + "select(S)" + f[j:]
    path = r"(?:\$\w+|\.)(?:\w+)?(?:\??(?:\.\w+|\[[^\[\]]*\]))*\??"
    f = re.sub(r"\(?\s*(?:\$\w+)?(?:\.\w+|\[[^\[\]]*\])*\.(?:%s)\s*(?://\s*\{\s*\})?\s*\)?\s*\|\s*to_entries(?:\[\])?"
               % "|".join(TF_JSON_MASKS), " M ", f)  # entries of a mask are key names and booleans
    f = re.sub(r"%s\s*\|\s*(?:keys_unsorted|keys|length|type)\b(?:\[\])?" % path, " K ", f)
    while re.search(r"\(\s*[KM]\s*\)", f):
        f = re.sub(r"\(\s*([KM])\s*\)", r" \1 ", f)
    f = f.replace("select(S)", " select ")
    for m in re.finditer(r"\b([KM])\s+as\s+\$(\w+)", f):
        safe_vars.add(m.group(2))
    for m in JQ_PATH.finditer(f):
        base, rest = m.group(1), m.group(2)
        kind = "safe" if base[1:] in safe_vars else "container"
        for field, index in re.findall(r"\.?(\w+)|\[([^\]]*)\]", rest):
            if kind != "container":
                break
            if field:
                kind = ("container" if field in TF_JSON_CONTAINERS else "safe" if field in TF_JSON_LEAVES
                        else "mask" if field in TF_JSON_MASKS else "bad:" + field)
            elif not re.fullmatch(r"\s*-?\d*\s*", index):
                kind = "bad:[%s]" % index
        if kind.startswith("bad:"):
            return "the filter prints `%s`, which can hold values" % kind[4:]
        after = f[m.end():].lstrip()
        if kind == "container" and not re.match(r"\||as\s+\$\w+", after):
                return "the filter prints `%s` whole, values included" % (base + rest)
    for w in re.findall(r"(?<![.$\w@])([A-Za-z_]\w*)\b(?!\s*:)", f):
        if w not in JQ_WORDS and w not in TF_JSON_LEAVES | TF_JSON_CONTAINERS | TF_JSON_MASKS:
            return "the filter calls `%s`, which the guard can't vet" % w
    return None


def check_terraform(binary, args, cwd, raw):
    flags = [a for a in args if a.startswith("-")]
    words = [a for a in args if not a.startswith("-")]
    chdir = next((a.split("=", 1)[1] for a in flags if a.startswith("-chdir=")), None)
    workdir = resolve(chdir, cwd) if chdir else cwd
    if not words:
        return None
    sub = words[0]
    if sub == "state":
        op = words[1] if len(words) > 1 else ""
        if op == "pull":
            return secret("`%s state pull`" % binary, "prints the whole state, secrets included")
        if op in {"list", "show"}:
            return None
        return ask("`%s state %s`" % (binary, op), "writes the state file")
    if sub == "workspace":
        return None if words[1:2] in (["list"], ["show"]) else ask("`%s workspace`" % binary, "changes workspace")
    if sub == "output" and (any(f in {"-json", "-raw"} for f in flags) or len(words) > 1):
        return secret("`%s output %s`" % (binary, " ".join(flags)), "prints sensitive outputs in clear")
    jq = re.search(r"\bshow\b[^|]*\|\s*jq\b(.*)", raw or "", re.S)
    why = jq_prints_values(jq.group(1)) if jq else None
    if sub == "show" and "-json" in flags and jq and not why:
        return None  # piped to a jq filter that prints addresses, actions, key names and masks, not values
    if sub == "show" and "-json" in flags:
        return ask("`%s show -json`" % binary, "can print sensitive values: %s. Filter it with jq to addresses, "
                   "actions and key names (`keys`, or inside `select()`)" % (why or "nothing filters it"))
    if sub == "console":
        return ask("`%s console`" % binary, "can evaluate and print sensitive values")
    if sub not in TF_READ:
        return ask("`%s %s`" % (binary, sub), "changes real infrastructure or the state")
    if sub == "init" and any(f.startswith(("-migrate-state", "-force-copy", "-reconfigure", "-from-module",
                                           "-plugin-dir")) for f in flags):
        return ask("`%s init` with that flag" % binary, "moves state or loads providers from an unchecked place")
    if sub == "providers" and len(words) > 1 and words[1] != "schema":
        return ask("`%s providers %s`" % (binary, words[1]), "writes provider files or the lock file")
    if sub in {"plan", "test"}:
        return iac_problem(workdir or cwd)
    return None


# --------------------------------------------------------------------------------------------------------------
# git: reads and local commits run; anything that rewrites files from history, pushes or runs programs asks.
# --------------------------------------------------------------------------------------------------------------
# git is local work, not devops: every git command runs, pushes and lost work included. Only three things stop it:
# printing a secret, writing the guard's own files, and a program git is told to start, which is checked or asks.
GIT_SECRET_SUBS = {"show", "diff", "log", "cat-file", "blame", "grep", "whatchanged"}
GIT_WRITE_SUBS = {"rm", "mv", "checkout", "restore", "reset", "clean", "apply", "am", "stash", "merge", "rebase",
                  "cherry-pick", "revert", "pull", "switch"}
GIT_RUN_KEYS = re.compile(r"^(alias\.|core\.(sshcommand|pager|editor|hookspath|fsmonitor|askpass|gitproxy)|"
                          r"(diff|merge|filter)\..*\.(command|driver|textconv|clean|smudge|process)|credential\.|"
                          r"gpg\.|sequence\.editor|pager\.|uploadpack\.|receivepack\.|remote\..*\.(uploadpack|"
                          r"receivepack)|include\.|includeif\.|protocol\.)", re.I)
GIT_RUN_FLAGS = {"--ext-diff", "--open-files-in-pager", "--upload-pack", "--receive-pack"}


def check_git(args, cwd, depth=0):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] in {"-C", "-c"}:
            key = args[i + 1].split("=", 1)[0] if i + 1 < len(args) else ""
            if args[i] == "-c" and GIT_RUN_KEYS.match(key):
                return ask("`git -c %s`" % key, "sets a program for git to run")
            i += 2
            continue
        if args[i] in {"--no-pager", "-P", "--no-optional-locks", "--paginate", "-p", "--bare",
                       "--literal-pathspecs", "--no-replace-objects"} or args[i].startswith(("--git-dir=",
                                                                                            "--work-tree=")):
            i += 1
            continue
        return ask("`git %s`" % args[i], "can override config or run a program")
    rest = args[i:]
    if not rest:
        return None
    sub, sargs = rest[0], rest[1:]
    plain = [a for a in sargs if not a.startswith("-")]
    flags = {a.split("=", 1)[0] for a in sargs if a.startswith("-")}
    for a in plain:  # git show HEAD:.env, git diff -- .env, git log -p -- .env
        path = a.split(":", 1)[1] if ":" in a and sub in {"show", "cat-file"} else a
        if is_secret(path, cwd) and sub in GIT_SECRET_SUBS:
            return secret("`git %s %s`" % (sub, a), "prints a secret file's contents")
    if sub in GIT_WRITE_SUBS and any(is_protected(a, cwd) for a in plain):
        return ask("`git %s` on a protected path" % sub, "changes the guard, its settings or a protected file")
    run_flags = flags & (GIT_RUN_FLAGS | ({"-O"} if sub == "grep" else set()))
    if run_flags:
        return ask("`git %s %s`" % (sub, sorted(run_flags)[0]), "runs a program the guard can't see")
    if any(a.startswith("--output=") and is_protected(a.split("=", 1)[1], cwd) for a in sargs):
        return ask("`git %s --output`" % sub, "writes a protected path")
    if sub == "config" and len(plain) >= 2 and GIT_RUN_KEYS.match(plain[0]):
        return ask("`git config %s`" % plain[0], "sets a program for git to run")
    inner = []  # the shell commands git is told to run: checked like any other command
    for k, a in enumerate(sargs):
        if sub == "rebase" and a in {"-x", "--exec"} and k + 1 < len(sargs):
            inner.append(sargs[k + 1])
        elif sub == "rebase" and a.startswith("--exec="):
            inner.append(a.split("=", 1)[1])
    if sub == "submodule" and plain[:1] == ["foreach"]:
        inner.append(" ".join(a for a in plain[1:]))
    hit = None
    for cmd in inner:
        hit = worse(hit, check_command(cmd, cwd, depth + 1))
    return hit


# --------------------------------------------------------------------------------------------------------------
# Inline and file Python: an AST allowlist. Pure computation runs; subprocess, network, cloud SDKs and dynamic
# code ask; reading a credential file is denied.
# --------------------------------------------------------------------------------------------------------------
PY_MODULES = {
    "json", "sys", "re", "os", "os.path", "collections", "itertools", "functools", "math", "statistics",
    "datetime", "time", "csv", "textwrap", "string", "difflib", "glob", "fnmatch", "hashlib", "base64",
    "decimal", "fractions", "pprint", "typing", "dataclasses", "enum", "shlex", "operator", "copy", "uuid",
    "random", "unicodedata", "heapq", "bisect", "calendar", "zoneinfo", "ipaddress", "html", "urllib.parse",
    "tomllib", "configparser", "struct", "binascii", "argparse", "pathlib", "yaml", "io", "contextlib",
    "logging", "gzip", "zipfile", "tarfile", "xml.etree.ElementTree", "email", "secrets", "ast", "tokenize",
    "token", "keyword", "py_compile", "tomli", "graphlib", "textwrap", "colorsys",
}
PY_OS_ATTRS = {"path", "environ", "getcwd", "listdir", "walk", "scandir", "stat", "sep", "linesep", "getenv",
               "cpu_count", "getpid", "curdir", "pardir", "extsep", "pathsep", "fspath", "makedirs", "mkdir"}
PY_SYS_ATTRS = {"argv", "stdin", "stdout", "stderr", "exit", "version", "version_info", "platform", "maxsize",
                "getsizeof", "byteorder", "path"}
PY_WHOLE_PACKAGES = {m for m in PY_MODULES if "." not in m} - {"os", "sys"}


# Modules that reach the network, a cloud or database API, or run code the guard can't read. Any other module is
# local work and runs. subprocess and os.system are read instead: the command they run is checked like a shell line.
PY_REMOTE = {"socket", "ssl", "urllib.request", "urllib3", "http.client", "requests", "httpx", "aiohttp",
             "websocket", "websockets", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "paramiko",
             "fabric", "pexpect", "ptyprocess", "pty", "boto3", "botocore", "aioboto3", "google.cloud",
             "googleapiclient", "google.auth", "azure", "kubernetes", "digitalocean", "pydo", "hcloud", "openstack",
             "pulumi", "psycopg", "psycopg2", "pymysql", "MySQLdb", "mysql", "pymongo", "motor", "redis", "pika",
             "kafka", "confluent_kafka", "sqlalchemy", "asyncpg", "grpc", "hvac", "slack_sdk", "github", "gitlab",
             "ctypes", "cffi", "importlib", "runpy", "code", "codeop", "multiprocessing.connection", "webbrowser",
             "dns", "scapy", "ansible", "ansible_runner", "docker", "pymssql", "pyodbc", "cx_Oracle", "oracledb",
             "snowflake", "clickhouse_driver", "clickhouse_connect", "cassandra", "elasticsearch", "opensearchpy",
             "influxdb_client", "nats", "zmq", "pysftp", "smbclient", "ldap3", "fsspec", "s3fs", "gcsfs", "minio"}
PY_RUNNERS = {"subprocess", "commands", "sh", "plumbum", "invoke", "asyncio.subprocess"}
PY_OS_RUN = {"system", "popen", "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
             "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "posix_spawn",
             "posix_spawnp", "fork", "forkpty", "kill", "killpg", "putenv", "chroot", "setuid", "setgid"}
PY_SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}


def py_module_ok(name):
    return not any(name == m or name.startswith(m + ".") for m in PY_REMOTE | PY_RUNNERS)


def py_argv(node, literals):
    """The words a subprocess call runs, with `__ARG__` for values only known at run time; None if unknowable."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and len(literals.get(node.id, ())) == 1:
        return next(iter(literals[node.id]))
    if isinstance(node, (ast.List, ast.Tuple)):
        out = []
        for e in node.elts:
            if isinstance(e, ast.Starred):
                out.append("__ARG__")
            elif isinstance(e, ast.Constant):
                out.append(str(e.value))
            elif isinstance(e, ast.Name) and len(literals.get(e.id, ())) == 1:
                out.append(next(iter(literals[e.id])))
            else:
                out.append("__ARG__")
        return out
    return None


def check_py_run(node, cwd, label, shell=False):
    """Check the command a subprocess/os.system call runs, the way a shell line is checked."""
    argv = py_argv(node.args[0], PY_LITERALS) if node.args else None
    if argv is None:
        for kw in node.keywords:
            if kw.arg == "args":
                argv = py_argv(kw.value, PY_LITERALS)
    if argv is None:
        return ask("%s running a computed command" % label, "runs a command the guard can't read")
    if isinstance(argv, str):
        try:
            h = check_command(argv, cwd, 1) if shell else check_segment_words(shlex.split(argv) or [""], cwd, 1, argv)
        except ValueError:
            return ask("%s running a command" % label, "could not be parsed")
    else:
        if not argv or "__ARG__" in argv[0]:
            return ask("%s running a computed command" % label, "runs a command the guard can't read")
        h = check_segment_words(list(argv), cwd, 1, " ".join(argv))
    return (h[0] + " (run by %s)" % label, h[1], h[2]) if h else None


PY_LITERALS = {}


PY_BANNED = {"exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "locals",
             "vars", "breakpoint", "__builtins__", "memoryview"}
PY_WRITE_MODE = re.compile(r"[wax+]")
EXTERNAL_PATH = re.compile(r"sys\.argv|input\s*\(|environ|getenv|stdin")
PROTECTED_HINT = re.compile(r"\.claude|\.mcp\.json|\.ssh|\.aws|\.kube|\.git/|\.gitconfig|\.zshrc|\.bashrc|\.profile|"
                            r"/etc/|site-packages|LaunchAgents|\.terraform|expanduser|Path\.home|HOME")


def py_code_writes(code):
    """True when inline Python could write a file or start a program, so its arguments may name what it changes."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in {"exec", "eval", "compile", "__import__", "getattr", "open"} and \
                not any(isinstance(c, ast.Call) and c.func is n for c in ast.walk(tree)):
            return True  # aliased or passed around: what it does can't be read
        if not isinstance(n, ast.Call):
            continue
        name = n.func.id if isinstance(n.func, ast.Name) else n.func.attr if isinstance(n.func, ast.Attribute) else ""
        if name == "open":
            mode = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg in {"mode", "flags"}), None)
            if mode is not None and not (isinstance(mode, ast.Constant) and not PY_WRITE_MODE.search(str(mode.value))):
                return True
        elif name in PY_SUBPROCESS_CALLS | {"system", "popen", "exec", "eval", "compile", "__import__", "getattr",
                                            "remove", "unlink", "rmdir", "rmtree", "rename", "replace", "move", "chmod",
                                            "copy", "copyfile", "copy2", "copytree", "write_text", "write_bytes",
                                            "symlink_to", "touch", "mkdir", "makedirs", "truncate", "dump"}:
            if name == "replace" and len(n.args) >= 2 and not (isinstance(n.func, ast.Attribute) and isinstance(
                    n.func.value, ast.Name) and n.func.value.id in {"os", "shutil"}):
                continue  # str.replace(old, new)
            return True
    return False


def check_python_code(code, cwd, label="inline Python"):
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return ask(label, "does not parse (%s), so it can't be checked" % exc.msg)
    literals = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    literals.setdefault(t.id, set()).add(node.value.value)
    global PY_LITERALS
    PY_LITERALS = literals
    # The protected-path hint is read from names and path-like strings, so prose naming `/.ssh/` doesn't count
    hint_text = " ".join(n.id if isinstance(n, ast.Name) else ast.unparse(n) if isinstance(n, ast.Attribute) else n.value
                         for n in ast.walk(tree) if isinstance(n, (ast.Name, ast.Attribute)) or
                         isinstance(n, ast.Constant) and isinstance(n.value, str) and not re.search(r"\s", n.value))
    hit = secret_use = None
    runners = {"subprocess"}  # names bound to the subprocess module or its functions
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            runners |= {a.asname for a in node.names if a.name == "subprocess" and a.asname}
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            runners |= {a.asname or a.name for a in node.names}
    called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    printed = set()  # nodes whose value goes straight to the screen: print(...), sys.stdout.write(...)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and (isinstance(n.func, ast.Name) and n.func.id == "print" or
                                        isinstance(n.func, ast.Attribute) and n.func.attr == "write" and
                                        "stdout" in ast.dump(n.func.value)):
            printed.update(id(x) for a in n.args for x in ast.walk(a))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "open" and id(node) not in called:
            hit = worse(hit, ask("%s aliasing open()" % label, "hides which files it writes"))
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            owner = node.func.value.id if isinstance(node.func, ast.Attribute) and isinstance(node.func.value,
                                                                                             ast.Name) else None
            if (owner in runners and name in PY_SUBPROCESS_CALLS) or (owner is None and name in runners
                                                                       and name in PY_SUBPROCESS_CALLS):
                shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value
                            for kw in node.keywords) or name in {"getoutput", "getstatusoutput"}
                hit = worse(hit, check_py_run(node, cwd, label, shell=shell))
            elif owner == "os" and name in {"system", "popen"}:
                hit = worse(hit, check_py_run(node, cwd, label, shell=True))
            str_replace = name == "replace" and owner not in {"os", "shutil"} and len(node.args) >= 2
            if not str_replace and name in {"remove", "unlink", "rmdir", "rmtree", "rename", "replace", "move",
                                            "chmod", "copy", "copyfile", "copy2", "copytree", "write_text",
                                            "write_bytes", "symlink_to", "touch"}:
                target = node.args[-1] if name in {"rename", "replace", "move", "copy", "copyfile", "copy2",
                                                   "copytree"} and node.args else (
                    node.args[0] if node.args else (node.func.value if isinstance(node.func, ast.Attribute) else None))
                lit = target.value if isinstance(target, ast.Constant) and isinstance(target.value, str) else (
                    next(iter(literals[target.id])) if isinstance(target, ast.Name) and len(literals.get(target.id, ())) == 1
                    else None)
                if lit and is_protected(lit, cwd):
                    hit = worse(hit, ask("%s changing `%s`" % (label, lit), "is a protected path"))
            if name in {"open", "read_text", "read_bytes"}:
                target = node.args[0] if node.args else (node.func.value if isinstance(node.func, ast.Attribute) else None)
                paths = set()
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    paths = {target.value}
                elif isinstance(target, ast.Name) and target.id in literals:
                    paths = literals[target.id]
                elif isinstance(target, ast.Call) and target.args and isinstance(target.args[0], ast.Constant):
                    paths = {str(target.args[0].value)}
                mode = "r"
                if name == "open" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                if PY_WRITE_MODE.search(mode) and not paths and PROTECTED_HINT.search(hint_text):
                    hit = worse(hit, ask("%s writing a computed path" % label, "the path comes from outside the code or "
                                         "points near a protected location"))
                for p in paths:
                    if not PY_WRITE_MODE.search(mode) and is_secret(p, cwd):
                        if id(node) in printed or not is_project_secret(p, cwd):
                            return secret("%s reading `%s`" % (label, p), "prints a secret file")
                        secret_use = secret_use or ask("%s reading `%s`" % (label, p), USE_SECRET)
                    if PY_WRITE_MODE.search(mode) and is_protected(p, cwd):
                        hit = worse(hit, ask("%s writing `%s`" % (label, p), "is a protected path"))
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not py_module_ok(alias.name):
                    if alias.name.split(".")[0] not in PY_RUNNERS and alias.name != "asyncio.subprocess":
                        hit = worse(hit, ask("%s importing `%s`" % (label, alias.name),
                                             "reaches the network, a cloud or database API, or runs hidden code"))
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                pass  # its calls are read below
            elif not node.level and not py_module_ok(node.module or ""):
                hit = worse(hit, ask("%s importing from `%s`" % (label, node.module),
                                     "reaches the network, a cloud or database API, or runs hidden code"))
            elif node.module == "os" and any(a.name in PY_OS_RUN for a in node.names):
                hit = worse(hit, ask("%s importing from os" % label, "reaches functions that run programs"))
            elif node.module == "sys" and any(a.name not in PY_SYS_ATTRS for a in node.names):
                hit = worse(hit, ask("%s importing from sys" % label, "reaches interpreter internals"))
        elif isinstance(node, ast.Name) and node.id in PY_BANNED:
            hit = worse(hit, ask("%s using `%s`" % (label, node.id), "runs code the guard can't see"))
        elif isinstance(node, ast.Attribute):
            if node.attr in {"create_subprocess_exec", "create_subprocess_shell"}:
                hit = worse(hit, ask("%s calling `%s`" % (label, node.attr), "runs a program the guard can't read"))
            elif node.attr.startswith("__") and node.attr.endswith("__") and node.attr not in {"__name__", "__doc__"}:
                hit = worse(hit, ask("%s touching `%s`" % (label, node.attr), "reaches interpreter internals"))
            elif isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr in PY_OS_RUN - {
                    "system", "popen"}:
                hit = worse(hit, ask("%s calling `os.%s`" % (label, node.attr), "runs a program or changes the process"))
            elif isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr in {"system", "popen"} \
                    and id(node) not in called:
                hit = worse(hit, ask("%s passing `os.%s` around" % (label, node.attr), "hides which command it runs"))
            elif isinstance(node.value, ast.Name) and node.value.id in runners and node.attr not in \
                    PY_SUBPROCESS_CALLS | {"PIPE", "DEVNULL", "STDOUT", "CalledProcessError", "TimeoutExpired",
                                           "CompletedProcess", "SubprocessError"}:
                hit = worse(hit, ask("%s using `subprocess.%s`" % (label, node.attr), "runs a program the guard can't read"))
            elif isinstance(node.value, ast.Name) and node.value.id in runners and id(node) not in called and \
                    node.attr in PY_SUBPROCESS_CALLS:
                hit = worse(hit, ask("%s passing `subprocess.%s` around" % (label, node.attr),
                                     "hides which command it runs"))
            elif isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr not in PY_SYS_ATTRS:
                hit = worse(hit, ask("%s touching `sys.%s`" % (label, node.attr), "reaches interpreter internals"))
    if secret_use and hit and hit[2] == "ask":  # name the secret use first, so the user sees it when asked
        return (secret_use[0], "%s. It also %s %s" % (secret_use[1], hit[0], hit[1]), "ask")
    return worse(hit, secret_use)


# --------------------------------------------------------------------------------------------------------------
# ssh: your ssh config is trusted (Claude can't edit it: ~/.ssh is protected). Tunnels run. A remote command
# runs when every part of it is a read; anything else asks; reading a secret file remotely is denied.
# --------------------------------------------------------------------------------------------------------------
SSH_FLAGS_WITH_ARG = set("bcDEeFIiJLlmOoPpQRSWw")
SSH_RISKY_OPTIONS = {"proxycommand", "localcommand", "permitlocalcommand", "remotecommand", "knownhostscommand",
                     "proxyusefdpass", "match"}
REMOTE_READ_ANY_ARGS = {
    "cd", "cat", "head", "ls", "stat", "wc", "grep", "egrep", "fgrep", "zgrep", "zcat", "df", "du", "free", "uptime",
    "ps", "uname", "id", "whoami", "lsblk", "findmnt", "md5sum", "sha256sum", "readlink", "realpath", "pwd",
    "netstat", "lsof", "last", "w", "who", "nproc", "lscpu", "getent", "dig", "nslookup", "host", "blkid",
    "lsb_release", "sort", "uniq", "cut", "awk", "sed", "tr", "less", "more", "echo", "printf", "true", "test",
    "curl", "nc", "ss", "ping", "traceroute", "tracepath", "mtr", "openssl", "jq", "env", "sleep", "vmstat",
    "iostat", "mpstat", "sar", "top", "htop", "free", "date", "hostnamectl", "systemd-analyze", "tail",
    "journalctl", "find", "dmesg", "file", "hostname", "timedatectl", "systemctl", "ip", "docker", "crontab",
    "sudo", "fail2ban-client", "cscli", "nginx", "apachectl", "needrestart", "lynis", "smartctl", "upsc",
    "chronyc", "ntpq", "mount", "lsmod", "sysctl", "ufw", "iptables", "nft", "apt", "dpkg", "rpm", "snap",
}
REMOTE_DENY_FLAGS = {
    "tail": {"-f", "-F", "--follow", "--retry"},
    "journalctl": {"-f", "--follow", "--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys",
                   "--update-catalog", "--vacuum-size", "--vacuum-time", "--vacuum-files"},
    "find": {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"},
    "dmesg": {"-c", "-C", "-D", "-E", "-n", "--clear", "--read-clear", "--console-off", "--console-on"},
    "date": {"-s", "--set"}, "file": {"-C", "--compile"}, "ss": {"-K", "--kill"}, "sed": {"-i", "--in-place"},
    "crontab": {"-e", "-r", "-i"}, "curl": {"-X", "--request", "-d", "--data", "-F", "--form", "-T", "--upload-file",
                                            "-o", "--output", "-O"},
    "awk": set(), "sysctl": {"-w", "--write", "-p", "--load"},
}
REMOTE_READ_VERBS = {
    "systemctl": {"status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files",
                  "list-timers", "list-sockets", "list-dependencies", "cat"},
    "timedatectl": {"status", "show", "timesync-status", "show-timesync"},
    "ufw": {"status"}, "iptables": {"-L", "-S", "--list", "--list-rules"}, "nft": {"list"},
    "apt": {"list", "show", "policy", "search"}, "dpkg": {"-l", "-L", "-s", "--list", "--status"},
    "rpm": {"-q", "-qa", "-qi", "-ql"}, "snap": {"list", "info"}, "fail2ban-client": {"status", "get", "ping"},
    "cscli": {"decisions", "alerts", "metrics", "bouncers", "machines", "hub", "version"},
    "nginx": {"-t", "-T", "-v", "-V"}, "apachectl": {"-t", "-S", "-M", "configtest"},
    "needrestart": {"-b", "-r"}, "lynis": {"audit", "show"}, "smartctl": {"-H", "-a", "-i", "-A", "-x"},
    "upsc": None, "chronyc": {"tracking", "sources", "sourcestats", "activity"}, "ntpq": {"-p", "-c"},
    "mount": None, "lsmod": None, "ip": {"a", "addr", "address", "r", "route", "link", "l", "neigh", "n", "rule"},
    "crontab": {"-l"}, "hostnamectl": {"status"}, "systemd-analyze": None,
}
REMOTE_DOCKER_READ = {"ps", "logs", "inspect", "images", "version", "info", "top", "port", "stats", "diff",
                      "events", "history"}
REMOTE_COMPOSE_READ = {"ps", "logs", "config", "ls", "images", "top", "version", "events"}


def bundled(args, flags):
    bad = {a.split("=", 1)[0] for a in args if a.startswith("-")} & flags
    for a in args:
        if a.startswith("-") and not a.startswith("--") and len(a) > 2:
            bad |= {"-" + ch for ch in a[1:]} & flags
    return bad


def remote_segment(words):
    """One remote command segment (already split on pipes and ;). None when it only reads."""
    if words and words[0] in {"bao", "vault"}:
        verbs = [w for w in words[1:] if not w.startswith("-")]
        if verbs[:1] in (["status"], ["version"]) or (verbs[1:2] == ["list"] and verbs[:1] in
                                                       (["auth"], ["audit"], ["secrets"], ["policy"], ["kv"])):
            return None  # names and seal state, not secret values
        if verbs[:1] in (["read"], ["token"]) or verbs[:2] in (["kv", "get"], ["kv", "read"]):
            return secret("remote `%s %s`" % (words[0], " ".join(verbs[:3])), "prints a secret")
        return ask("remote `%s %s`" % (words[0], " ".join(verbs[:2])), "is a secrets tool the guard can't vet")
    while words and words[0] in {"sudo", "-n", "-E"}:
        words = words[1:]
    while words and ASSIGNMENT.match(words[0]):
        words = words[1:]
    if not words:
        return None
    binary = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    if binary == "curl":  # `-o /dev/null` only throws the body away (used with -w to print the status code)
        args = [a for k, a in enumerate(args) if not (a in {"-o", "--output"} and args[k + 1:k + 2] == ["/dev/null"])
                and not (k and args[k - 1] in {"-o", "--output"} and a == "/dev/null") and a != "--output=/dev/null"]
    plain = [a for a in args if not a.startswith("-")]
    for a in plain:
        if is_secret(a, "/"):
            return secret("remote `%s %s`" % (binary, a), "prints a secret file")
    if binary == "env" and not args:
        return secret("remote `env`", "prints every environment variable, secrets included")
    if binary in REMOTE_DENY_FLAGS and bundled(args, REMOTE_DENY_FLAGS[binary]):
        return ask("remote `%s %s`" % (binary, " ".join(sorted(bundled(args, REMOTE_DENY_FLAGS[binary])))),
                   "writes, deletes or never returns")
    if binary == "awk" and any(re.search(r"system|getline|>", a) for a in args):
        return ask("remote awk program", "can run commands or write files")
    if binary == "sed" and any(re.search(r"(^|[;{}\n])\s*[0-9,$/!]*\s*[wWe]\b|/[gpIiM0-9]*[we](\s|;|$)", a)
                               for a in args):
        return ask("remote sed script", "can write files or run commands")
    if binary == "hostname" and plain:
        return ask("remote `hostname %s`" % plain[0], "sets the hostname")
    if binary == "docker":
        if not plain:
            return None
        sub = plain[0]
        if sub == "compose":
            rest = positional(args[args.index("compose") + 1:], {"-p", "-f", "--project-name", "--file",
                                                                    "--env-file", "--profile", "--project-directory"})
            after = args[args.index(rest[0]) + 1:] if rest and rest[0] in args else []
            if rest and rest[0] in REMOTE_COMPOSE_READ and not (rest[0] == "logs" and bundled(after, {"-f", "--follow"})):
                return None
            return ask("remote `docker compose %s`" % (rest[0] if rest else ""), "changes containers on the host")
        if sub in {"container", "image", "network", "volume"} and len(plain) > 1 and plain[1] in {"ls", "list",
                                                                                                    "inspect", "logs", "ps"}:
            return None
        after = args[args.index(sub) + 1:]
        if sub == "stats" and "--no-stream" not in after:
            return ask("remote `docker stats`", "never returns without --no-stream")
        if sub in REMOTE_DOCKER_READ and not (sub == "logs" and bundled(after, {"-f", "--follow"})):
            return None
        if sub == "exec":
            return ask("remote `docker exec`", "runs a command inside a container")
        return ask("remote `docker %s`" % sub, "changes containers on the host")
    if binary in REMOTE_READ_VERBS:
        verbs = REMOTE_READ_VERBS[binary]
        if verbs is None:
            return None
        first = next((a for a in args if a in verbs or not a.startswith("-")), None)
        if (first in verbs) or (binary in {"iptables", "dpkg", "rpm", "nginx", "apachectl", "needrestart",
                                           "smartctl", "ntpq"} and bundled(args, verbs)):
            if binary == "ip" and set(plain) & {"add", "del", "delete", "change", "replace", "set", "flush"}:
                return ask("remote `ip %s`" % " ".join(plain), "changes networking")
            return None
        return ask("remote `%s %s`" % (binary, " ".join(args[:2])), "is not a read-only %s command" % binary)
    if binary in REMOTE_READ_ANY_ARGS:
        return None
    return ask("remote `%s`" % binary, "is not on the remote read-only list")


def check_remote(command):
    """A remote command string: every pipe/; segment must read; substitutions and redirects to files ask."""
    if re.search(r"`|\$\(", command):
        return ask("remote command `%s`" % command[:60], "uses command substitution, which runs on the host")
    try:
        segs, _subs = split_shell(command)
    except ValueError:
        return ask("remote command `%s`" % command[:60], "could not be parsed")
    hit = None
    for seg in segs:
        try:
            words = shlex.split(seg)
        except ValueError:
            return ask("remote command `%s`" % seg[:60], "could not be parsed")
        clean = []
        skip = False
        for i, w in enumerate(words):
            if skip:
                skip = False
                continue
            m = REDIRECT.match(w)
            if m and (m.group(2).startswith(">")) and not m.group(3):
                target = m.group(4) or (words[i + 1] if i + 1 < len(words) else "")
                if target not in {"/dev/null", "/dev/stderr", "/dev/stdout"} and not target.startswith("&"):
                    return ask("remote redirect into `%s`" % target, "writes a file on the host")
                skip = not m.group(4)
                continue
            clean.append(w)
        hit = worse(hit, remote_segment(clean))
        if hit and hit[2] == "deny":
            return hit
    return hit


def check_ssh(args):
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-") or a == "-":
            break
        body = a[1:]
        j = 0
        while j < len(body):
            ch = body[j]
            if ch in SSH_FLAGS_WITH_ARG:
                value = body[j + 1:]
                if not value:
                    i += 1
                    value = args[i] if i < len(args) else ""
                key = re.split(r"[=\s]", value, 1)[0].lower()
                if ch == "o" and key in SSH_RISKY_OPTIONS:
                    return ask("`ssh -o %s`" % value.split("=")[0], "runs a local command")
                if ch == "o" and key in {"userknownhostsfile", "globalknownhostsfile", "controlpath", "identityagent"} \
                        and is_protected(re.split(r"[=\s]", value, 1)[-1], os.getcwd()):
                    return ask("`ssh -o %s`" % value, "writes into a protected file")
                if ch == "E" and is_protected(value, os.getcwd()):
                    return ask("`ssh -E %s`" % value, "writes into a protected file")
                if ch == "R":
                    return ask("`ssh -R`", "opens a port on the remote host back into this machine")
                break
            j += 1
        i += 1
    if i >= len(args):
        return ask("`ssh` with no host", "can't be checked")
    remote = " ".join(args[i + 1:])
    if not remote.strip():
        if any(a in {"-N", "-fN", "-Nf"} or (a.startswith("-") and "N" in a and not a.startswith("--")) for a in args[:i]):
            return None  # tunnel only (-N): forwards ports, runs nothing
        return ask("an interactive `ssh` session", "can't be checked — pass the read-only command instead")
    return check_remote(remote)


# --------------------------------------------------------------------------------------------------------------
# make, scripts and package scripts: read what they would run and check that instead.
# --------------------------------------------------------------------------------------------------------------


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


MAKE_TEXT_FUNCS = {
    "firstword": lambda a: (a.split() or [""])[0], "lastword": lambda a: (a.split() or [""])[-1],
    "strip": lambda a: " ".join(a.split()), "dir": lambda a: " ".join(os.path.dirname(w) + "/" for w in a.split()),
    "notdir": lambda a: " ".join(os.path.basename(w) for w in a.split()),
}


def make_expand(text, variables, depth=0):
    if depth > 10:
        return text
    out = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]", lambda m: variables.get(m.group(1), m.group(0)), text)
    out = re.sub(r"\$\((%s) ([^()$]*)\)" % "|".join(MAKE_TEXT_FUNCS),
                 lambda m: MAKE_TEXT_FUNCS[m.group(1)](m.group(2)), out)
    return out if out == text else make_expand(out, variables, depth + 1)


def make_rules(directory, makefile, overrides):
    names = [makefile] if makefile else ["GNUmakefile", "makefile", "Makefile"]
    path = next((os.path.join(directory, n) for n in names if os.path.isfile(os.path.join(directory, n))), None)
    variables, rules, problems, seen = {"MAKE": "make", "CURDIR": directory,
                                        "MAKEFILE_LIST": os.path.basename(path or "Makefile")}, {}, [], set()
    load_time = []  # shell commands make runs while reading the file (:= and != values)
    default = [None]

    def parse(p):
        if p in seen:
            return
        if not os.path.isfile(p):
            problems.append("includes `%s`, which doesn't exist yet (it may be generated)" % os.path.relpath(p, directory))
            return
        seen.add(p)
        lines = (read_text(p) or "").split("\n")
        current, define = None, None
        k = 0
        while k < len(lines):
            raw = lines[k]
            while raw.endswith("\\") and k + 1 < len(lines):  # line continuation
                k += 1
                raw = raw[:-1] + " " + lines[k].lstrip()
            k += 1
            if define is not None:
                if raw.strip() == "endef":
                    variables[define[0]] = "\n".join(define[1])
                    define = None
                else:
                    define[1].append(raw)
                continue
            if raw.startswith("\t"):
                if current:
                    for t in current:
                        rules.setdefault(t, ([], []))[1].append(raw.strip().lstrip("@-+"))
                continue
            line = raw.split("#", 1)[0].rstrip()
            m_def = re.match(r"^(?:export\s+|override\s+)?define\s+([A-Za-z_][A-Za-z0-9_.-]*)", line)
            if m_def:
                define = (m_def.group(1), [])
                continue
            inc = re.match(r"^(-?)(include|sinclude)\s+(.+)$", line)
            m_var = re.match(r"^(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:=|::=|\+=|!=|=)\s*(.*)$",
                             line)
            m_rule = re.match(r"^([^:=#\t][^:=#]*?)\s*::?\s*([^=].*)?$", line)
            if inc:
                for f in make_expand(inc.group(3), variables).split():
                    target = os.path.join(directory, f)
                    if inc.group(1) or inc.group(2) == "sinclude":
                        if os.path.isfile(target):
                            parse(target)
                    else:
                        parse(target)
                current = None
            elif m_var:
                name, op, val = m_var.groups()
                if op == "!=":
                    load_time.append(make_expand(val, variables))
                elif op in {":=", "::="} and "$(shell" in val:
                    load_time.extend(re.findall(r"\$\(shell ([^)]*)\)", make_expand(val, variables)))
                if name in overrides:
                    pass
                elif op == "?=" and name in variables:
                    pass
                elif op == "+=":
                    variables[name] = (variables.get(name, "") + " " + val).strip()
                else:
                    variables[name] = val
                current = None
            elif m_rule and not line.startswith(" "):
                targets = [t for t in make_expand(m_rule.group(1), variables).split()]
                rest = m_rule.group(2) or ""
                prereq_part, _, inline = rest.partition(";")
                prereqs = make_expand(prereq_part.split("|")[0], variables).split()
                for t in targets:
                    rules.setdefault(t, ([], []))[0].extend(prereqs)
                    if inline.strip():
                        rules[t][1].append(inline.strip().lstrip("@-+"))
                    if default[0] is None and not t.startswith(".") and "%" not in t:
                        default[0] = t
                current = targets
            elif line.strip():
                current = None

    variables.update(overrides)
    if path:
        parse(path)
    return variables, rules, default[0], problems, path, load_time


def check_make(args, cwd, depth):
    directory, makefile, targets, overrides, i = cwd, None, [], {}, 0
    while i < len(args):
        a = args[i]
        if a in ("-C", "--directory") and i + 1 < len(args):
            directory = os.path.join(directory, args[i + 1])
            i += 2
            continue
        if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
            makefile = args[i + 1]
            i += 2
            continue
        if a.startswith(("--directory=", "--file=", "--makefile=", "--eval", "-E")):
            if a.startswith("--directory="):
                directory = os.path.join(directory, a.split("=", 1)[1])
            elif a.startswith(("--file=", "--makefile=")):
                makefile = a.split("=", 1)[1]
            else:
                return ask("`make %s`" % a, "evaluates make code given on the command line")
        elif ASSIGNMENT.match(a):
            name, _, value = ASSIGNMENT.match(a).groups()
            overrides[name] = value
        elif not a.startswith("-") and not a.isdigit():
            targets.append(a)
        i += 1
    variables, rules, default, problems, path, load_time = make_rules(directory, makefile, overrides)
    if not path:
        return None  # no makefile: make will just fail
    if problems:
        return ask("`make`", "the makefile %s, so what it runs can't be checked" % problems[0])
    hit, visited = None, set()
    for cmd in load_time:
        h = check_command(cmd, directory, depth + 1)
        if h:
            hit = worse(hit, (h[0] + " (run by the makefile while loading: `%s`)" % cmd[:80], h[1], h[2]))

    def walk(target, chain):
        nonlocal hit
        if target in visited:
            return
        visited.add(target)
        if target not in rules:
            if any("%" in t for t in rules) and not os.path.exists(os.path.join(directory, target)):
                hit = worse(hit, ask("`make %s`" % target, "uses a pattern rule the guard can't follow"))
            return
        prereqs, recipe = rules[target]
        for p in prereqs:
            walk(p, chain + [p])
        for line in recipe:
            cmd = make_expand(line, variables).replace("$(shell ", "$(").replace("$$", "$")
            h = check_command(cmd, directory, depth + 1)
            if h:
                hit = worse(hit, (h[0] + " (in `make %s`, line `%s`)" % (" → ".join(chain), cmd[:80]), h[1], h[2]))
            if hit and hit[2] == "deny":
                return

    for t in targets or ([default] if default else []):
        walk(t, [t])
    return hit


SHELL_BINARIES = {"bash", "sh", "zsh", "dash", "ksh"}
JS_REMOTE = re.compile(r"\bfetch\s*\(|\bhttps?\.(request|get)\b|\bnet\.(connect|createConnection)|"
                       r"\baxios(\.\w+)?\s*\(|require\(['\"]axios|"
                       r"require\(['\"](node-fetch|got|undici|ws|@aws-sdk/|aws-sdk|@google-cloud/|@azure/)")
JS_STRING = re.compile(r"""(['"`])((?:\\.|(?!\1).)*)\1""")
BATS_SYNTAX = re.compile(r"""(?m)^\s*@test\s+("[^"]*"|'[^']*')\s*\{|\brun\s+(?=\S)|^\s*load\s+\S+""")
SECRET_TOOLS = {"vault": {"read", "get", "kv", "token"}, "bao": {"read", "get", "kv", "token"}, "op": {"read", "get", "item", "inject", "run"},
                "sops": set(), "gh": {"token"}, "pass": {"show"}, "bw": {"get", "export"},
                "doppler": {"secrets", "run"}, "infisical": {"secrets", "export", "run"}, "chamber": {"read", "export",
                                                                                                    "exec"},
                "aws-vault": {"exec", "export"}}


def check_script(path, cwd, depth, interpreter=None):
    text = read_text(path)
    rel = os.path.relpath(path, cwd)
    if text is None:
        return ask("`%s`" % rel, "is too big or unreadable to check")
    first = text.split("\n", 1)[0]
    kind = interpreter or (re.sub(r"^#!\s*(/usr/bin/env\s+)?", "", first).split()[0].rsplit("/", 1)[-1]
                           if first.startswith("#!") else ("python3" if path.endswith(".py") else "sh"))
    if kind.startswith("python"):
        return check_python_code(text, cwd, label="`%s`" % rel)
    if kind in SHELL_BINARIES:
        h = check_command(text, cwd, depth + 1)
        return (h[0] + " (in `%s`)" % rel, h[1], h[2]) if h else None
    return ask("`%s`" % rel, "is a %s program the guard can't check" % kind)


def check_package_script(manager, args, cwd, depth):
    words = positional(args, {"--prefix", "-C", "--cwd", "--dir"})
    if not words or words[0] in {"ls", "list", "view", "info", "outdated", "why", "audit", "help", "config",
                                 "--version", "version"}:
        return None
    name = words[1] if words[0] in {"run", "run-script"} and len(words) > 1 else words[0]
    try:
        scripts = json.loads(read_text(os.path.join(cwd, "package.json")) or "{}").get("scripts", {})
    except ValueError:
        scripts = {}
    if name in scripts and (words[0] in {"run", "run-script", "test", "start"} or manager != "npm"):
        h = check_command(scripts[name], cwd, depth + 1)
        return (h[0] + " (in `%s run %s`)" % (manager, name), h[1], h[2]) if h else None
    return ask("`%s %s`" % (manager, " ".join(words[:2])), "installs packages or runs code the guard can't check")


DOCKER_RUN_VALUE_FLAGS = {"-v", "--volume", "-e", "--env", "-w", "--workdir", "-p", "--publish", "--name",
                          "--network", "--entrypoint", "--env-file", "-u", "--user", "--mount", "--platform",
                          "-h", "--hostname", "-l", "--label", "--restart", "--memory", "-m", "--cpus",
                          "--add-host", "--dns", "--log-driver", "--pull"}
CLI_IMAGES = re.compile(r"(^|/)(terraform|tofu|opentofu|aws-cli|azure-cli|cloud-sdk|google-cloud-cli|doctl|kubectl|"
                        r"helm|ansible|logcli|mimirtool)(:|@|$)")


def check_docker(args, cwd, depth, env_host):
    top = []
    k = 0
    while k < len(args) and args[k].startswith("-"):
        top.append(args[k])
        if args[k] in {"-H", "--host", "-c", "--context", "--config"} and k + 1 < len(args):
            top.append(args[k + 1])
            k += 1
        k += 1
    rest = args[k:]
    remote = env_host or any(t in {"-H", "--host", "-c", "--context"} or t.startswith(("-H=", "--host=",
                                                                                        "--context=")) for t in top)
    if remote:
        h = remote_segment(["docker"] + rest)
        return (h[0].replace("remote ", "remote-daemon "), h[1], h[2]) if h else None
    if not rest:
        return None
    sub = rest[0]
    if sub in {"inspect", "container"} and not any(a.startswith(("-f", "--format")) for a in rest) \
            and (sub == "inspect" or rest[1:2] == ["inspect"]):
        return secret("`docker inspect`", "prints the container's environment, secrets included; add --format "
                      "with the fields you need")
    if sub == "exec":
        inner = positional(rest[1:], {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file"})[1:]
        h = remote_segment(inner) if inner else None
        if h and h[2] == "deny":
            return (h[0].replace("remote", "container"), h[1], h[2])
    if sub in {"run", "create", "exec"}:
        sargs, j, mounts, envfiles, entrypoint = rest[1:], 0, [], [], None
        while j < len(sargs) and sargs[j].startswith("-"):
            f = sargs[j].split("=", 1)[0]
            if f in DOCKER_RUN_VALUE_FLAGS:
                val = sargs[j].split("=", 1)[1] if "=" in sargs[j] else (sargs[j + 1] if j + 1 < len(sargs) else "")
                if f in {"-v", "--volume", "--mount"}:
                    mounts.append(val)
                if f == "--env-file":
                    envfiles.append(val)
                if f == "--entrypoint":
                    entrypoint = os.path.basename(val)
                j += 1 if "=" in sargs[j] else 2
                continue
            j += 1
        for m in mounts:
            src = m.split(":", 1)[0].replace("source=", "").split(",")[0]
            if is_secret(src, cwd) or any(p in (resolve(src, cwd) or src) + "/" for p in ("/.aws/", "/.ssh/",
                                                                                         "/.kube/", "/.azure/",
                                                                                         "/.config/gcloud/")):
                return ask("`docker %s -v %s`" % (sub, m), "hands your credentials to a container")
        image_and_cmd = sargs[j:]
        if sub == "run" and entrypoint in OBS_READS and image_and_cmd:  # e.g. --entrypoint amtool prom/alertmanager
            return check_segment_words([entrypoint] + image_and_cmd[1:], cwd, depth + 1,
                                       " ".join([entrypoint] + image_and_cmd[1:]))
        if sub == "run" and image_and_cmd and CLI_IMAGES.search(image_and_cmd[0]):
            tool = CLI_IMAGES.search(image_and_cmd[0]).group(2)
            tool = {"aws-cli": "aws", "azure-cli": "az", "cloud-sdk": "gcloud", "google-cloud-cli": "gcloud",
                    "opentofu": "tofu"}.get(tool, tool)
            inner = image_and_cmd[1:]
            if inner and inner[0] == tool:
                inner = inner[1:]
            return check_segment_words([tool] + inner, cwd, depth + 1, " ".join([tool] + inner))
        return None
    return None  # local docker: the user's own machine


# --------------------------------------------------------------------------------------------------------------
# Shell parsing (from write-guard v2): quote-aware split, substitutions, heredocs, redirects.
# --------------------------------------------------------------------------------------------------------------


def split_shell(text):
    """Quote-aware split into (segments, substitutions). Raises ValueError."""
    segments, subs, cur = [], [], []
    i, n, quote = 0, len(text), None

    def find_close(start, open_ch, close_ch):
        depth, j, q = 1, start, None
        while j < n:
            c = text[j]
            if q:
                if c == "\\" and q == '"':
                    j += 2
                    continue
                if c == q:
                    q = None
            elif c in "'\"":
                q = c
            elif c == "\\":
                j += 2
                continue
            elif c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        raise ValueError("unbalanced %s" % open_ch)

    while i < n:
        c = text[i]
        if quote is None and c == "(" and text[i - 1:i] == "=" and re.match(r"[A-Za-z_]\w*\+?=$",
                                                                               "".join(cur).split()[-1] if cur and "".join(cur).split() else ""):
            end = find_close(i + 1, "(", ")")  # NAME=( ... ): an array assignment, not a subshell
            cur.append(text[i:end + 1])
            i = end + 1
            continue
        if quote != "'" and TEST_MODE and text.startswith("$((", i):
            end = text.find("))", i)
            if end != -1:
                cur.append("0")  # arithmetic in a test file: tolerated, like PATH changes
                i = end + 2
                continue
        if quote != "'" and text.startswith("$((", i):
            end = text.find("))", i)
            body = text[i + 3:end] if end != -1 else ""
            names = set(re.findall(r"[A-Za-z_]\w*", body))
            tainted = any(re.search(r"(?:^|[\s;&|(])%s=(['\"]?)([^\s;&|]*)" % re.escape(n), text) and
                          any(re.search(r"\[|`", v.group(2)) or (v.group(1) == "'" and "$(" in v.group(2))
                              for v in re.finditer(r"(?:^|[\s;&|(])%s=(['\"]?)([^\s;&|]*)" % re.escape(n), text))
                          for n in names) or re.search(r"\b(read|mapfile|readarray)\b", text)
            if end != -1 and not tainted and re.fullmatch(r"[\w\s+\-*/%<>=!&|?:,$#{}()]*", body) and "$(" not in \
                    body and "[" not in body:
                cur.append("0")  # plain arithmetic on names and numbers: no command or array index to run
                i = end + 2
                continue
        if quote is None and text.startswith("((", i) and (i == 0 or text[i - 1] in " \t\n;&|"):
            end = text.find("))", i)
            body = text[i + 2:end] if end != -1 else ""
            if end != -1 and re.fullmatch(r"[\w\s+\-*/%<>=!&|?:,;$#{}]*", body) and "$(" not in body and not any(
                    re.search(r"(?:^|[\s;&|(])%s=['\"]?[^\s;&|]*[\[`]" % re.escape(n), text)
                    for n in set(re.findall(r"[A-Za-z_]\w*", body))):
                cur.append("true")  # (( i++ )) or for (( i = 0; i < n; i++ )): plain arithmetic, no command
                i = end + 2
                continue
        if quote != "'" and (text.startswith(("$((", "${(", "$["), i) or (quote is None and text.startswith("((", i))):
            raise ValueError("arithmetic or zsh expansion flags evaluate variable contents as code")
        if quote == "'":
            cur.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\":
            cur.append(text[i:i + 2])
            i += 2
            continue
        if c in "$<>" and text[i + 1:i + 2] == "(" and not (c == "$" and text[i + 2:i + 3] == "("):
            end = find_close(i + 2, "(", ")")
            subs.append(text[i + 2:end])
            cur.append("__SUBST__")
            i = end + 1
            continue
        if c == "`":
            end = text.find("`", i + 1)
            while end != -1 and text[end - 1] == "\\":
                end = text.find("`", end + 1)
            if end == -1:
                raise ValueError("unbalanced backtick")
            subs.append(text[i + 1:end])
            cur.append("__SUBST__")
            i = end + 1
            continue
        if quote == '"':
            cur.append(c)
            if c == '"':
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
            cur.append(c)
            i += 1
            continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;|&("):  # comment to end of line
            nl = text.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if c == "&" and (text[i - 1:i] == ">" or text[i + 1:i + 2] == ">"):
            cur.append(c)
            i += 1
            continue
        if c in ";\n|&(":
            segments.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if quote:
        raise ValueError("unbalanced %s" % quote)
    segments.append("".join(cur))
    return [s for s in segments if s.strip()], subs


HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def extract_heredocs(command):
    lines = command.split("\n")
    out, bodies, i = [], {}, 0
    while i < len(lines):
        line = lines[i]
        pending = []

        def repl(m):
            if m.start() > 0 and line[m.start() - 1] == "<":
                return m.group(0)
            key = "__HEREDOC_%d__" % (len(bodies) + len(pending))
            pending.append((key, m.group(3), bool(m.group(2)), m.group(1) == "-"))
            return "< " + key
        out.append(HEREDOC.sub(repl, line))
        i += 1
        for key, delim, quoted, strip_tabs in pending:
            body = []
            while i < len(lines):
                cand = lines[i].lstrip("\t") if strip_tabs else lines[i]
                i += 1
                if cand == delim:
                    break
                body.append(lines[i - 1])
            else:
                raise ValueError("unterminated heredoc %s" % delim)
            bodies[key] = ("\n".join(body), quoted)
    return "\n".join(out), bodies


REDIRECT = re.compile(r"^(\d*|&)(>>?|>\||<<<|<>|<)(&?)(.*)$")

# Local commands that only read, compute or print.
READERS = {
    "cat", "head", "tail", "wc", "ls", "stat", "grep", "egrep", "fgrep", "rg", "zgrep", "zcat", "diff", "cmp",
    "comm", "cut", "tr", "uniq", "nl", "tac", "rev", "fold", "paste", "join", "column", "fmt", "expand",
    "unexpand", "jq", "yq", "base64", "xxd", "od", "hexdump", "strings", "shasum", "sha256sum", "md5", "md5sum",
    "cksum", "basename", "dirname", "realpath", "readlink", "pwd", "echo", "printf", "true", "false", "test", "[",
    "[[", "]]", "cal", "uname", "whoami", "id", "sw_vers", "which", "type", "whence", "sleep", "seq", "du", "df",
    "ps", "pgrep", "uptime", "vm_stat", "dig", "nslookup", "host", "ping", "lsof", "netstat", "tree", "file",
    "wait", "jobs", ":", "pushd", "popd", "shift", "read", "exit", "return", "break", "continue", "getopts",
    "umask", "ulimit", "mktemp", "sha1sum", "trivy", "checkov", "tflint", "nproc", "less", "more", "sort", "date",
    "traceroute", "mtr", "whois", "ss", "nc", "openssl", "shellcheck", "gitleaks", "terraform-docs", "infracost",
    "tfsec", "semgrep", "kubeconform", "kube-linter", "hadolint", "actionlint", "yamllint", "fzf",
    "kubescape", "prowler", "zizmor", "jscpd",
    "lynis", "time", "tput", "locale", "hostname", "env", "printenv", "set", "export", "declare", "typeset",
    "local", "readonly", "unset", "setopt", "unsetopt", "shopt", "cd", "command", "awk", "gawk", "sed", "find",
    "xargs", "curl", "wget", "python", "python3", "tee", "ssh-keygen", "systemctl", "journalctl", "dmesg",
}
WRITERS = {"cp", "mv", "rm", "rmdir", "mkdir", "touch", "ln", "chmod", "install", "truncate", "tee", "unlink"}
DELETERS = {"rm", "rmdir", "unlink", "shred", "srm"}
# Python modules for databases and remote stores, beyond PY_REMOTE's list.
# Tools with their own checker above; a script or test that starts one by name gets checked.
INFRA_NAMES = {"aws", "aws2", "az", "gcloud", "doctl", "kubectl", "oc", "helm", "terraform", "tofu", "terragrunt",
               "pulumi", "ansible", "ansible-playbook", "ssh", "scp", "rsync", "git", "docker", "vault", "op", "sops",
               "gh", "curl", "wget", *OBS_READS}

# Programs that reach infrastructure, a remote or shared service, or change this machine beyond the project.
# Everything else that isn't checked above is a local program and runs.
_REMOTE = "reaches infrastructure or a remote service"
INFRA_TOOLS = {**{t: _REMOTE for t in (
    "gsutil", "bq", "s3cmd", "s5cmd", "rclone", "mc", "eksctl", "kops", "argocd", "flux", "istioctl", "linkerd",
    "velero", "kubeadm", "talosctl", "skaffold", "tilt", "packer", "vagrant", "nomad", "consul", "waypoint",
    "boundary", "cdk", "cdktf", "sam", "serverless", "sls", "copilot", "amplify", "firebase", "vercel", "netlify",
    "heroku", "flyctl", "fly", "railway", "wrangler", "oci", "ibmcloud", "hcloud", "linode-cli", "vultr-cli", "scw",
    "civo", "openstack", "exo", "crane", "gcrane", "skopeo", "oras", "cosign", "regctl", "psql", "mysql", "mariadb",
    "mongosh", "mongo", "redis-cli", "cqlsh", "sqlcmd", "pg_dump", "pg_restore", "mysqldump", "etcdctl",
    "rabbitmqadmin", "rabbitmqctl", "kafka-topics", "kafka-console-producer", "kcat", "nats", "glab", "tea",
    "stripe", "sentry-cli", "virsh", "ipmitool", "racadm", "cloudflared", "flarectl", "tailscale", "helmfile",
    "kubectx", "kubens", "telnet", "ftp", "lftp", "socat", "nmap", "masscan", "mosh", "ssh-copy-id", "terraformer",
    "cf-terraforming", "s3fs", "aws-nuke", "cloud-nuke")},
    "act": "runs CI workflows with the secrets in .actrc or -s; a dry run (-n) runs without asking",
    **{t: "runs code the guard can't read" for t in (
        "osascript", "open", "npx", "bunx", "pnpx", "uvx", "tmux", "screen", "expect", "php", "lua", "pwsh",
        "powershell", "deno", "bun", "java", "Rscript", "tclsh", "wish", "irb", "jshell", "xdg-open", "at", "batch")},
    **{t: "stops processes on this machine (a tunnel, a server, the user's own work)" for t in (
        "kill", "pkill", "killall")},
    **{t: "changes this machine's network, services or disks" for t in (
        "iptables", "ip6tables", "nft", "ufw", "pfctl", "route", "networksetup", "launchctl", "crontab", "shutdown",
        "reboot", "halt", "poweroff", "diskutil", "mount", "umount", "dd", "mkfs", "fdisk", "parted", "wg",
        "wg-quick", "chown", "chflags", "defaults", "security", "csrutil", "spctl", "tmutil")},
}
PKG_MANAGERS = {"brew", "apt", "apt-get", "yum", "dnf", "apk", "pacman", "port", "pip", "pip3", "pipx", "gem",
                "cargo", "conda", "mamba", "snap", "flatpak", "softwareupdate", "mas", "asdf", "mise", "tfenv",
                "tfswitch", "helm-plugin"}
PKG_READ = {"list", "ls", "show", "info", "search", "freeze", "outdated", "deps", "leaves", "doctor", "config",
            "check", "help", "home", "desc", "uses", "which", "current", "where", "env", "inspect", "policy"}


# Tools the guard has no checker for are judged by shape, not by name. Most cloud and SaaS CLIs read as
# `<tool> <thing...> <action>`: the action words say whether it reads or changes something. Whether the tool reaches
# a remote service is judged from signals the project and machine already give: the project's tool list
# (.claude/goodbehavior/guard-tools.txt), a credential variable or .env key named after the tool, or a config folder
# for it in HOME. A write word asks; only read words run; anything else asks for a remote tool and runs for a local one.
WRITE_VERBS = {
    "create", "new", "add", "insert", "put", "post", "set", "unset", "update", "upsert", "edit", "patch", "modify",
    "change", "replace", "rename", "move", "mv", "copy", "cp", "clone", "fork", "delete", "del", "remove", "rm",
    "rmi", "destroy", "drop", "truncate", "flush", "flushall", "flushdb", "purge", "prune", "wipe", "erase", "clear",
    "reset", "nuke", "kill", "terminate", "stop", "start", "restart", "reboot", "shutdown", "halt", "poweroff",
    "power", "suspend", "resume", "pause", "unpause", "freeze", "thaw", "up", "down", "run", "exec", "invoke",
    "trigger", "apply", "deploy", "undeploy", "redeploy", "release", "publish", "unpublish", "push", "upload",
    "sync", "import", "promote", "demote", "rollout", "rollback", "revert", "restore", "migrate", "upgrade",
    "downgrade", "install", "uninstall", "provision", "deprovision", "decommission", "teardown", "scale", "resize",
    "rebuild", "reimage", "deallocate", "allocate", "attach", "detach", "associate", "disassociate",
    "assign", "unassign", "bind", "unbind", "link", "unlink", "connect", "disconnect", "enable", "disable",
    "activate", "deactivate", "approve", "reject", "merge", "close", "reopen", "lock", "unlock", "grant", "revoke",
    "rotate", "renew", "regenerate", "issue", "sign", "tag", "untag", "label", "unlabel", "annotate", "cordon",
    "uncordon", "drain", "taint", "untaint", "failover", "switchover", "reconcile", "refresh", "login", "logout",
    "register", "deregister", "unregister", "subscribe", "unsubscribe", "send", "notify", "cancel", "abort",
    "accept", "decline", "authorize", "deauthorize", "invite", "transfer", "expire", "archive", "unarchive",
    "snapshot", "backup", "commit", "write", "mount", "unmount", "expose", "open", "ssh", "console", "shell",
    "tunnel", "proxy", "forward", "listen", "serve",
}
READ_VERBS = {
    "list", "ls", "get", "show", "describe", "view", "status", "info", "inspect", "logs", "log", "events", "top",
    "history", "version", "versions", "help", "whoami", "me", "account", "search", "find", "query", "lookup",
    "check", "validate", "lint", "diff", "plan", "preview", "explain", "summary", "stats", "metrics", "health",
    "ping", "doctor", "audit", "watch", "tail", "config", "context", "contexts", "current", "regions", "zones",
    "types", "sizes", "images", "count", "exists", "print", "read", "cat", "dry-run", "dryrun", "completion",
    # local work: build tools and package managers keep registry tokens in the environment too
    "build", "test", "tests", "compile", "fmt", "format", "bench", "generate", "gen", "package", "assemble",
}
SECRET_NOUNS = {"secret", "secrets", "token", "tokens", "password", "passwords", "passwd", "credential",
                "credentials", "creds", "apikey", "apikeys"}
REVEAL_VERBS = {"get", "show", "read", "reveal", "export", "download", "print", "value", "values", "access", "view",
                "cat", "decrypt", "dump"}
# On a remote tool these can print the app's settings, secrets included (`heroku config`, `netlify env:list`).
ENV_NOUNS = {"env", "envs", "environment", "variables", "vars", "config", "configs"}
REVEAL_FLAGS = re.compile(r"^--?(reveal|plain|plaintext|show-secrets?|show-values?|decrypt|unmask|raw|"
                          r"with-decryption|show-token|insecure-print)(=|$)")
# Remote tools whose reads still ask: a "read" of a data store or a scanner can still print data or hit a network.
KEEP_ASKING = {"psql", "mysql", "mariadb", "mongosh", "mongo", "redis-cli", "cqlsh", "sqlcmd", "pg_dump",
               "pg_restore", "mysqldump", "etcdctl", "kcat", "nats", "kafka-console-producer", "telnet", "ftp",
               "lftp", "socat", "nmap", "masscan", "mosh", "ssh-copy-id", "aws-nuke", "cloud-nuke", "terraformer",
               "cf-terraforming", "s3fs", "kubectx", "kubens", "stripe"}
CRED_WORDS = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|USERNAME|ENDPOINT|API|URL|HOST)")
CRED_TEXT = re.compile(r"(?im)^\s*[\"']?[\w.-]*(token|api[_-]?key|secret|password|passwd|access[_-]?key|auth)[\w.-]*"
                       r"[\"']?\s*[:=]\s*\S")


def tool_stems(name):
    """`linode-cli` -> {linode-cli, linode}; `neonctl` -> {neonctl, neon}; `upctl` -> {upctl, up}."""
    base = name.lower()
    stems = {base}
    for suffix in ("-cli", "_cli", "cli", "-ctl", "ctl", "adm", "-admin", "admin"):
        if base.endswith(suffix) and len(base) > len(suffix):
            stems.add(base[:-len(suffix)].rstrip("-_"))
    return {t for t in stems if t}


def project_tools(cwd):
    """`remote: <tool>` and `local: <tool>` lines in .claude/goodbehavior/guard-tools.txt (adoption writes it from
    the tools the project says it uses; the user can add lines). The file is protected, so Claude can't edit it
    without asking."""
    text = read_text(os.path.join(repo_root(cwd), ".claude", "goodbehavior", "guard-tools.txt")) or ""
    remote, local = set(), set()
    for line in text.splitlines():
        m = re.match(r"^\s*(remote|local)\s*:\s*([^\s#]+)", line)
        if m:
            (remote if m.group(1) == "remote" else local).add(m.group(2))
    return remote, local


def remote_signal(name, cwd):
    """Why a program the guard has no checker for looks like it reaches a remote service, or None."""
    remote, local = project_tools(cwd)
    if name in local:
        return None
    if name in remote:
        return "is listed as a remote tool in .claude/goodbehavior/guard-tools.txt"
    if INFRA_TOOLS.get(name) == _REMOTE:
        return _REMOTE
    stems = {t for t in tool_stems(name) if len(t) >= 3}
    prefixes = tuple(t.upper().replace("-", "_") + "_" for t in stems)

    def cred_var(var):
        var = var.upper()
        return any(var.startswith(p) and CRED_WORDS.search(var[len(p):]) for p in prefixes)
    for var in os.environ:
        if cred_var(var):
            return "has credentials in the environment (`%s`)" % var  # weak: registry tokens look the same
    root = repo_root(cwd)
    for f in (".env", ".env.example", ".secret"):
        for m in re.finditer(r"(?m)^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=", read_text(os.path.join(root, f)) or ""):
            if cred_var(m.group(1)):
                return "has credentials in the project's `%s` (`%s`)" % (f, m.group(1))
    # A config in HOME counts only when it holds a credential: editors and linters keep configs there too.
    for t in stems:
        for c in (os.path.join(HOME, ".config", t), os.path.join(HOME, "." + t),
                  *(os.path.join(HOME, ".config", t + ext) for ext in (".yaml", ".yml", ".toml", ".json", ".ini")),
                  os.path.join(HOME, "Library", "Application Support", t)):
            files = [c] if os.path.isfile(c) else sorted(glob.glob(os.path.join(c, "*")) + glob.glob(
                os.path.join(c, "*", "*")))[:30] if os.path.isdir(c) else []
            for f in files:
                if os.path.isfile(f) and os.path.getsize(f) <= 65_536 and CRED_TEXT.search(read_text(f) or ""):
                    return "has a login saved in your home folder (`%s`)" % f.replace(HOME, "~", 1)
    return None


def verb_parts(word):
    """`config:set` -> [config, set]; `delete-instance` -> [delete, instance]; `web-1` -> [web, 1]."""
    return [p for p in re.split(r"[:._/-]+", word.lower()) if p]


def check_by_shape(name, args, cwd):
    """A program with no checker of its own: judge it by its action words and whether it reaches a remote."""
    if args in (["--version"], ["version"], ["-v"], ["-V"], ["-h"], ["--help"], ["help"]):
        return None
    words = positional(args[:args.index("--")] if "--" in args else args)
    words = [w for w in words if " " not in w and len(w) < 64]  # a quoted script or query is not an action word
    parts = [p for w in words for p in [w.lower(), *verb_parts(w)]]
    writes = [w for w in words if w.lower() in WRITE_VERBS or any(p in WRITE_VERBS for p in verb_parts(w))]
    reads = [w for w in words if w.lower() in READ_VERBS or verb_parts(w)[:1] and verb_parts(w)[0] in READ_VERBS
             or verb_parts(w)[-1:] and verb_parts(w)[-1] in READ_VERBS]
    signal = remote_signal(name, cwd)
    shown = " ".join([name] + words[:3])
    if set(parts) & SECRET_NOUNS and (set(parts) & REVEAL_VERBS or any(REVEAL_FLAGS.match(a) for a in args)):
        if signal:
            return secret("`%s`" % shown, "looks like it prints a secret (the tool %s)" % signal)
        return ask("`%s`" % shown, "looks like it reads a secret")
    if not signal:
        if name in project_tools(cwd)[1]:
            return None  # listed as local in guard-tools.txt
        if writes and set(parts) & {"destroy", "terminate", "deprovision", "decommission", "deallocate", "failover",
                                    "teardown", "nuke", "poweroff", "deploy", "undeploy", "redeploy", "publish",
                                    "rollout", "rollback", "provision", "switchover"}:
            return ask("`%s`" % shown, "its action word usually reaches infrastructure or a remote service (mark the "
                       "tool `local:` in .claude/goodbehavior/guard-tools.txt if it doesn't)")
        return None  # a local program: it works on this machine, which git and the user can put back
    if name in KEEP_ASKING:
        return ask("`%s`" % name, INFRA_TOOLS.get(name, signal))
    if writes:
        return ask("`%s`" % shown, "`%s` changes something, and the tool %s" % (writes[0], signal))
    if set(parts) & ENV_NOUNS:
        return ask("`%s`" % shown, "can print the service's settings, secrets included, and the tool %s" % signal)
    if reads:
        return None  # only read words: a listing or a status
    if signal.startswith("has credentials in the "):
        return None  # a token variable alone is a weak signal (build tools keep registry tokens too): writes ask
    return ask("`%s`" % shown, "the guard can't tell whether it reads or changes something, and the tool %s" % signal)


def outside_project(path, cwd):
    """True when a path to delete lies outside the project and the temp folders (the user's other files)."""
    real = resolve(path, cwd)
    values = loop_values(path) if real is None else None
    if values is not None:
        return any(outside_project(v, cwd) for v in values)
    if real is None:
        return False  # a variable: `rm -r` on one still asks below; a plain `rm "$tmp"` runs, as before
    roots = {os.path.realpath(repo_root(cwd)), os.path.realpath(cwd), os.path.realpath(tempfile.gettempdir()),
             "/tmp", "/private/tmp", "/private/var/folders", "/var/folders"}
    return not any(real == r or real.startswith(r.rstrip("/") + "/") for r in roots)
KEYWORDS = {"!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "(", ")", "esac",
            ";;"}


GREP_NO_LINES = {"-c", "--count", "-q", "--quiet", "--silent", "-l", "--files-with-matches", "-L",
                 "--files-without-match"}
# Provider APIs a read with the project's token may go to without asking. Other hosts count when the project's own
# .env or .env.example names them (GITEA_URL=https://git.example.com), so a token can't be sent somewhere new.
API_HOSTS = re.compile(r"^(api\.cloudflare\.com|api\.digitalocean\.com|api\.github\.com|gitlab\.com|"
                       r"management\.azure\.com|graph\.microsoft\.com|[a-z0-9-]+\.googleapis\.com|"
                       r"api\.hetzner\.cloud|api\.linode\.com|api\.vultr\.com|api\.scaleway\.com|"
                       r"api\.machines\.dev|api\.fly\.io|api\.vercel\.com|api\.netlify\.com|sentry\.io|"
                       r"[a-z0-9-]+\.grafana\.net|api\.datadoghq\.(com|eu)|api\.pagerduty\.com|api\.tailscale\.com)$")


def api_host_ok(host, cwd):
    if API_HOSTS.match(host):
        return True
    root = repo_root(cwd)
    for f in (".env", ".env.example", ".secret"):
        text = read_text(os.path.join(root, f)) or ""
        if re.search(r"^[^#\n]*=\s*['\"]?https://%s(?::\d+)?(?:[/'\"\s]|$)" % re.escape(host), text, re.M | re.I):
            return True
    git_config = read_text(os.path.join(root, ".git", "config")) or ""  # the project's own git remotes
    return bool(re.search(r"^\s*url\s*=\s*(?:https://|ssh://)?(?:[^@/\s]+@)?%s(?:[:/]|$)" % re.escape(host),
                          git_config, re.M | re.I))


def check_segment(segment, bodies, cwd, depth, raw):
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return ask("an unparseable command", "could not be parsed, so it can't be shown to be safe")
    words, stdin_bodies = [], []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        m = REDIRECT.match(t)
        if (m and (m.group(1) or m.group(2)) and t not in {"<", ">"}) or t in {"<", ">", ">>", "<<<", "&>", "2>",
                                                                               "2>>", "1>", "&>>"}:
            op, dup, target = (m.group(2), m.group(3), m.group(4)) if m else (t, "", "")
            if not target:
                i += 1
                target = tokens[i] if i < len(tokens) else ""
            if op.startswith(">") or op == "<>":
                if not dup and target not in {"/dev/null", "/dev/stdout", "/dev/stderr"} and is_protected(target, cwd):
                    return ask("a redirect into `%s`" % target, "changes the guard, its settings or a protected file")
            elif op == "<" and target in bodies:
                stdin_bodies.append(bodies[target])
            elif op == "<" and is_secret(target, cwd):
                return secret("reading `%s`" % target, "prints a secret file")
            i += 1
            continue
        words.append(t)
        i += 1
    while words and words[0] in KEYWORDS:
        words = words[1:]
    if words and words[-1].endswith(")") and words[-1].count(")") > words[-1].count("("):
        words[-1] = words[-1][:-1]
        words = [w for w in words if w]
    if not words or words[0] in {"for", "select", "case", "in", "esac", "function"}:
        return None
    if words[0].endswith(")") and len(words[0]) > 1 and "=" not in words[0]:
        words = words[1:]
    return check_segment_words(words, cwd, depth, raw, stdin_bodies)


def awk_code_only(prog):
    """Blank out awk string and /regex/ literals, so a `|` or `>` inside them isn't taken for a pipe or a redirect.
    One pass, like awk's own lexer: a `/` starts a regex only where an operand can't precede it."""
    out, i, prev = [], 0, ""
    while i < len(prog):
        c = prog[i]
        if c == '"' or (c == "/" and (prev == "" or prev in "(,~!{};&|=<>?:+-*%^\n")):
            j, in_class = i + 1, False
            while j < len(prog):
                if prog[j] == "\\":
                    j += 2
                    continue
                if c == "/" and prog[j] == "[":
                    in_class = True
                elif in_class and prog[j] == "]":
                    in_class = False
                elif prog[j] == c and not in_class:
                    break
                elif prog[j] == "\n":
                    break
                j += 1
            out.append(c + c)
            i, prev = j + 1, "x"
            continue
        out.append(c)
        if not c.isspace() or c == "\n":
            prev = c
        i += 1
    return "".join(out)


def check_segment_words(words, cwd, depth, raw, stdin_bodies=()):
    docker_host = None
    while words and re.match(r"^[A-Za-z_]\w*\[[^\]`]*\]\+?=", words[0]) and "__SUBST__" not in words[0].split("=")[0]:
        words = words[1:]  # MAP[key]=value: an array element set; its value is data
    while words and ASSIGNMENT.match(words[0]):
        name, _, value = ASSIGNMENT.match(words[0]).groups()
        if value.startswith("("):  # NAME=( a b c ): an array assignment; its elements are data, not commands
            k = 0
            while k < len(words) and not words[k].endswith(")"):
                k += 1
            words = words[k + 1:]
            continue
        if name == "DOCKER_HOST" and value.startswith("ssh://"):
            docker_host = value
        elif name == "IFS" and next((w for w in words if not ASSIGNMENT.match(w)), None) == "read":
            pass  # `while IFS= read -r line`: splits a line, runs nothing
        elif len(words) > 1 or DANGEROUS_ENV.match(name):
            h = env_problem(name)
            if h:
                return h
        words = words[1:]
    if not words:
        return None
    binary, args = words[0], words[1:]

    # Wrappers that run another command.
    while binary in {"nohup", "nice", "stdbuf", "caffeinate", "command", "time", "timeout", "env", "exec",
                     "sudo", "doas"}:
        if binary == "command" and args[:1] in (["-v"], ["-V"]):
            return None
        if binary in {"env", "printenv"} and not [a for a in args if not ASSIGNMENT.match(a) and not a.startswith("-")]:
            return secret("`%s`" % binary, "prints every environment variable, secrets included")
        if binary in {"sudo", "doas"}:
            rest = [a for a in args if not a.startswith("-")]
            if not rest:
                return ask("`%s`" % binary, "runs as root")
            h = check_segment_words(rest, cwd, depth, raw)
            return h or ask("`sudo %s`" % rest[0], "runs as root on this machine")
        if binary == "env":
            j = 0
            while j < len(args) and (args[j].startswith("-") or ASSIGNMENT.match(args[j])):
                if args[j] in {"-S", "--split-string"}:
                    return ask("`env -S`", "splits a string into a command the guard can't see")
                if ASSIGNMENT.match(args[j]):
                    h = env_problem(ASSIGNMENT.match(args[j]).group(1))
                    if h:
                        return h
                j += 1
            args = args[j:]
        elif binary == "timeout":
            j = 0
            while j < len(args) and args[j].startswith("-"):
                j += 1
            args = args[j + 1:]
        elif binary == "nice":
            args = args[2:] if args[:1] == ["-n"] else args
        else:
            args = [a for a in args if not a.startswith("-")] if binary in {"stdbuf", "caffeinate", "time"} else args
        if not args:
            return None
        binary, args = args[0], args[1:]

    name = binary.rsplit("/", 1)[-1]
    if binary in FUNCS or (binary.endswith("()") and binary[:-2] in FUNCS) or binary == "function" or (
            TEST_MODE and re.match(r"(skip|assert_\w+|refute_\w+|bats_\w+|fail)$", binary)):
        return None  # a function defined in this script: its body is checked where it is defined
    if not args and re.search(r"[*?]", binary) and "/" in binary:
        return None  # a `case` pattern such as http://*|https://*), split at its `|`
    if TEST_MODE and ("$" in binary or "__SUBST__" in binary):
        return None  # a test calling a helper or a mocked tool by a variable; literal commands are still checked
    if name == "__SUBST__" or "__SUBST__" in binary or "__ARG__" in binary:
        return ask("a command named by substitution", "can't be checked")
    if "$" in binary:
        return ask("a command named by a variable (`%s`)" % binary, "can't be checked")
    if name in {"[["} and set(args) & {"-eq", "-ne", "-lt", "-le", "-gt", "-ge"} and any(
            "$" in re.sub(r"\$(#|\?|!|\$|\{#[A-Za-z_]\w*\})", "", a) for a in args):
        return ask("a `[[` numeric test on a variable", "evaluates the variable's contents as code")
    if name in {"eval", "alias", "unalias", "hash", "enable", "trap", "fc", "coproc", "zmodload", "autoload",
                "emulate", "let", "builtin"}:
        return ask("`%s`" % name, "runs or renames code the guard can't see")

    # Secrets, whatever reads them.
    if name in {"printenv"}:
        names = [a for a in args if not a.startswith("-")]
        if not names or any(SECRET_ENV.search(n) for n in names):
            return secret("`printenv %s`" % " ".join(names), "prints a secret environment variable")
        return None
    if name in {"echo", "printf"} and any(re.search(r"\$\{?([A-Za-z_]\w*)", a) and
                                          SECRET_ENV.search(re.search(r"\$\{?([A-Za-z_]\w*)", a).group(1))
                                          for a in args):
        return secret("`%s $…`" % name, "prints a secret environment variable")
    if name in {"set", "export", "declare", "typeset"} and (not args or args[:1] in (["-p"], ["-x"], ["-px"])):
        return secret("`%s %s`" % (name, " ".join(args)), "prints every variable, secrets included")
    if name in {"export", "declare", "typeset", "local", "readonly", "unset"}:
        for a in args:
            m = ASSIGNMENT.match(a)
            h = env_problem(m.group(1) if m else a) if not a.startswith("-") else None
            if h:
                return h
        return None
    if name in {"source", "."}:
        target = args[0] if args else ""
        if is_secret(target, cwd):
            return None  # loads secrets into the environment without printing them
        real = resolve(target, cwd)
        if real and os.path.isfile(real) and depth < MAX_DEPTH:
            return check_script(real, cwd, depth, interpreter="sh")
        return ask("`%s %s`" % (name, target), "runs a file the guard can't find")
    in_place = name in {"sed", "gsed", "perl"} and any(a.startswith(("-i", "--in-place")) or a == "-pi" for a in args)
    reads_files = not in_place and name not in WRITERS and name not in {"kubectl", "k", "oc", "helm", "k9s","cd", "mkdir", "stat", "ls", "test", "[", "[[", "git",
                                                         "basename", "dirname", "realpath", "readlink", "file",
                                                         "touch", "chmod", "source", "."}
    # scanners hand a kubeconfig to their client to connect; they don't print it
    passed = {k + 1 for k, a in enumerate(args[:-1]) if name in {"kubescape", "prowler", "trivy", "kube-bench"}
              and a in {"--kubeconfig", "--kubeconfig-file"}}
    if name in {"grep", "egrep", "fgrep", "zgrep", "rg"} and bundled(args, GREP_NO_LINES):
        reads_files = False  # prints a count, a file name or nothing: no line of the file reaches the screen
    for k, a in enumerate(args):
        value = a.split("=", 1)[1] if "=" in a and not a.startswith("-") else a
        if k in passed:
            continue
        if reads_files and not a.startswith("-") and (is_secret(a, cwd) or is_secret(value, cwd)):
            return secret("reading `%s`" % a, "prints a secret file")
    if name in {"cp", "scp", "rsync", "tar", "zip"} and any(is_secret(a, cwd) for a in args[:-1] if not a.startswith("-")):
        return ask("copying a secret file", "it could then be read from the copy")

    if name in {"grep", "egrep", "fgrep", "zgrep", "rg"}:
        if bundled(args, GREP_NO_LINES):
            return None
        recursive = name == "rg" or bundled(args, {"-r", "-R", "--recursive", "--dereference-recursive"})
        if recursive:
            hidden = name != "rg" or bool(bundled(args, {"--hidden", "-u", "--no-ignore", "-uu", "-uuu"})) \
                or any(re.fullmatch(r"-u+", a) for a in args)
            excludes = [a.split("=", 1)[1] for a in args if a.startswith(("--exclude=", "--glob=!", "-g!"))]
            excludes += [args[k + 1].lstrip("!") for k, a in enumerate(args[:-1]) if a in {"--exclude", "-g", "--glob"}]
            exclude_dirs = [a.split("=", 1)[1] for a in args if a.startswith("--exclude-dir=")]
            exclude_dirs += [args[k + 1] for k, a in enumerate(args[:-1]) if a == "--exclude-dir"]
            plain = [a for a in args if not a.startswith("-")]
            given = plain if any(a in {"-e", "-f", "--regexp", "--file"} for a in args) else plain[1:]
            paths = [a for a in given if os.path.isdir(os.path.join(cwd, a))] if given else ["."]
            follow = bool(bundled(args, {"-R", "--dereference-recursive"} if name != "rg" else {"-L", "--follow"}))
            includes = [a.split("=", 1)[1] for a in args if a.startswith("--include=")]
            includes += [args[k + 1] for k, a in enumerate(args[:-1]) if a == "--include"]
            for p in paths:
                found = secrets_under(os.path.join(cwd, p), excludes, hidden=hidden, follow_links=follow,
                                      exclude_dirs=exclude_dirs)
                if includes and name != "rg":  # grep searches only files whose name matches an --include
                    found = [f for f in found if any(fnmatch.fnmatch(os.path.basename(f), g) for g in includes)]
                if found:
                    dirs = sorted({f.split(os.sep)[0] for f in found if os.sep in f})
                    tip = "".join(" --exclude-dir=%s" % d for d in dirs[:3])
                    return secret("`%s` over `%s`" % (name, p), "would search secret files (%s). Add "
                                  "--exclude='.env*' --exclude='*.secret'%s or narrow the path"
                                  % (", ".join(found[:3]), tip))
        return None

    if name in TOOL_READS or name == "govc":
        verbs = positional(args)
        if name == "govc" and verbs and GOVC_READ.match(verbs[0]):
            return None
        if name in TOOL_READS and verbs and verbs[0] in TOOL_READS[name] and not any(
                a.startswith("--repair") for a in args):
            return None
        return ask("`%s %s`" % (name, " ".join(verbs[:1])), "is not a known read-only %s command" % name)
    if name in OBS_READS or name == "grafana":
        return check_obs(name, args)
    if name in LOAD_TOOLS:
        verbs = positional(args)
        if name == "k6" and verbs[:1] in (["version"], ["inspect"], ["help"]) or args in (["--version"], ["-h"],
                                                                                         ["--help"]):
            return None
        return user_only("`%s`" % name, "sends load at a service, and load can take down a shared or production "
                         "environment")
    if name == "gh":
        verbs = positional(args, {"-R", "--repo", "-q", "--jq", "-t", "--template", "--json", "-L", "--limit",
                                  "-H", "--header", "--hostname"})
        if verbs[:2] == ["auth", "status"] and "--show-token" not in args and "-t" not in args:
            return None
        if verbs[:1] and verbs[0] in {"repo", "pr", "issue", "run", "release", "workflow", "search", "label",
                                      "cache"} and verbs[1:2] and verbs[1] in {"view", "list", "diff", "checks",
                                                                               "status", "issues", "prs", "repos",
                                                                               "code", "commits"}:
            return None
        if verbs[:1] == ["api"] and not bundled(args, {"-X", "--method", "-f", "-F", "--field", "--raw-field",
                                                       "--input"}):
            return None  # GET only
    if name in SECRET_TOOLS:
        verbs = positional(args, {"-format", "--format", "-field", "--field", "--vault", "--account", "-o", "--output"})
        if name in {"vault", "bao"} and (verbs[:1] in (["status"], ["version"]) or verbs[1:2] == ["list"]
                                         and verbs[:1] in (["auth"], ["audit"], ["secrets"], ["policy"], ["kv"])):
            return None  # status and listings show names, not secret values
        reads = SECRET_TOOLS[name]
        if verbs[:1] == ["kv"]:
            hit = verbs[1:2] in (["get"], ["read"])
        elif name in {"vault", "bao"}:
            hit = bool(verbs[:1]) and verbs[0] in reads
        else:
            hit = any(v in reads for v in verbs[:2])
        if (name == "sops" and bundled(args, {"-d", "--decrypt", "-i"})) or (name != "sops" and hit):
            return secret("`%s %s`" % (name, " ".join(verbs[:3])), "prints a secret")
        return ask("`%s %s`" % (name, " ".join(verbs[:2])), "is a secrets tool the guard can't vet")
    if name in {"aws", "aws2"}:
        return check_aws(args)
    if name == "az":
        return check_az(args)
    if name == "gcloud":
        return check_gcloud(args)
    if name == "doctl":
        return check_doctl(args)
    if name in {"kubectl", "k", "oc"}:
        return check_kubectl(args)
    if name == "helm":
        return check_helm(args)
    if name in {"terraform", "tofu", "opentofu"}:
        return check_terraform(name, args, cwd, raw)
    if name == "terragrunt":
        verbs = [a for a in args if not a.startswith("-")]
        inner = verbs[1:] if verbs[:1] == ["run-all"] else verbs
        return check_terraform("terragrunt", inner, cwd, raw)
    if name in {"make", "gmake"}:
        return check_make(args, cwd, depth) if depth < MAX_DEPTH else ask("`make`", "is nested too deep to check")
    if name == "git":
        return check_git(args, cwd, depth)
    if name == "ssh":
        return check_ssh(args)
    if name in {"scp", "sftp", "rsync"} and any(":" in a for a in args if not a.startswith("-")):
        return ask("`%s` to or from another host" % name, "copies files across machines")
    if name == "docker":
        return check_docker(args, cwd, depth, docker_host)
    if name in {"npm", "yarn", "pnpm"}:
        return check_package_script(name, args, cwd, depth)
    if name == "pulumi":
        sub = positional(args, {"-C", "--cwd", "-s", "--stack"})[:1]
        return None if sub in (["preview"], ["whoami"], ["about"], ["version"]) or sub == ["stack"] and "ls" in args \
            else ask("`pulumi %s`" % (sub[0] if sub else ""), "changes real infrastructure")
    if name in {"ansible-playbook", "ansible"}:
        if name == "ansible-playbook" and "--check" in args:
            return None
        if name == "ansible" and (flag_value(args, "-m", "--module-name") or "command") in {"ping", "setup",
                                                                                            "ansible.builtin.ping",
                                                                                            "ansible.builtin.setup"}:
            return None
        return ask("`%s`" % name, "changes the target hosts")
    if name == "ansible-inventory":
        return None
    if name in SHELL_BINARIES:
        if any(a == "-n" or (re.fullmatch(r"-[a-zA-Z]+", a) and "n" in a[1:] and "c" not in a[1:]) for a in args):
            return None  # -n (noexec): parses the script for syntax errors, runs nothing
        for k, a in enumerate(args):
            if a == "-c" and k + 1 < len(args):
                if TEST_MODE and re.fullmatch(r'"?\$\{?\w+\}?"?', args[k + 1].strip()):
                    return None  # a test running a workflow step it rendered into a variable, tools mocked
                return check_command(args[k + 1], cwd, depth + 1)
        script = next((a for a in args if not a.startswith("-")), None)
        if script is not None:
            real = resolve(script, cwd) if script else None
            if real and os.path.isfile(real) and depth < MAX_DEPTH:
                return check_script(real, cwd, depth, interpreter=name)
            if TEST_MODE and (real is None or not os.path.isfile(real)):
                return None  # a test running the project's own script by a variable path, with its tools mocked
        return ask("`%s`" % name, "runs a script or stdin the guard can't see")
    if name == "node":
        if not args or args[0] in {"--version", "-v"}:
            return None
        files = [a for a in args if not a.startswith("-")]
        if "-e" in args or "-p" in args or "--eval" in args or not files:
            return ask("`node` running inline code", "runs JavaScript the guard can't check")
        for f in files:
            for path in (glob.glob(os.path.join(cwd, f)) or [os.path.join(cwd, f)]):
                text = read_text(path)
                rel = os.path.relpath(path, cwd)
                if text is None:
                    return ask("`node %s`" % rel, "is too big or unreadable to check")
                if JS_REMOTE.search(text):
                    return ask("`node %s`" % rel, "reaches the network or a cloud API")
                if "child_process" in text:  # the programs it starts: any string naming a checked tool asks
                    for m in JS_STRING.finditer(text):
                        words = m.group(2).split()
                        if words and words[0] in INFRA_NAMES | set(INFRA_TOOLS) | PKG_MANAGERS:
                            return ask("`node %s` starting `%s`" % (rel, words[0]), "runs a program that %s" % _REMOTE)
        return None
    if name == "bats":
        hit = None
        for f in [a for a in args if not a.startswith("-")]:
            for path in sorted(glob.glob(os.path.join(cwd, f)) + glob.glob(os.path.join(cwd, f, "*.bats"))):
                if os.path.isfile(path):
                    raw_text = read_text(path) or ""
                    helpers = ""  # functions from `load <helper>` files, so calls to them are known
                    for name_ in re.findall(r"(?m)^\s*load\s+['\"]?([\w./-]+)", raw_text):
                        base = os.path.join(os.path.dirname(path), name_)
                        helpers += (read_text(base if base.endswith(".bash") else base + ".bash") or "") + "\n"
                    text = BATS_SYNTAX.sub(" ", helpers + raw_text)
                    h = check_command(text, cwd, depth + 1, test_mode=True)
                    if h:
                        hit = worse(hit, (h[0] + " (in `%s`)" % os.path.relpath(path, cwd), h[1], h[2]))
        return hit
    if name in {"python", "python3"}:
        given = [a for k, a in enumerate(args) if not a.startswith("-") and not (k and args[k - 1] in {"-c", "-m"})]
        if "-c" in args and args.index("-c") + 1 < len(args) and not py_code_writes(args[args.index("-c") + 1]):
            given = []  # `python3 -c 'print(quote(sys.argv[1]))' "$1"`: code that writes nothing can't write its args
        hit_arg = next((a for a in given if is_protected(a, cwd)), None)
        if hit_arg:
            return ask("`python` given `%s`" % hit_arg, "may write the guard, its settings or a protected file")
        if "-c" in args:
            k = args.index("-c")
            return check_python_code(args[k + 1] if k + 1 < len(args) else "", cwd)
        if "-m" in args:
            mod = args[args.index("-m") + 1] if args.index("-m") + 1 < len(args) else ""
            return None if mod in {"json.tool", "py_compile", "pytest", "unittest", "venv"} \
                else ask("`python -m %s`" % mod, "runs a module the guard can't check")
        script = None if "-" in args else next((a for a in args if not a.startswith("-")), None)
        if script:  # `python3 - a b`: the program is stdin, a and b are its arguments
            real = resolve(script, cwd)
            if real and os.path.isfile(real):
                return check_script(real, cwd, depth, interpreter="python3")
            return ask("`python %s`" % script, "runs a file the guard can't find yet. Write the file first, then run it "
                       "in a separate command so the guard can read it")
        for body, _quoted in stdin_bodies:
            h = check_python_code(body, cwd)
            if h:
                return h
        return None if stdin_bodies else ask("`python` reading stdin", "runs code the guard can't see")
    if "/" in binary:
        real = resolve(binary, cwd)
        if real and os.path.isfile(real) and os.path.dirname(real) not in path_dirs() and depth < MAX_DEPTH:
            return check_script(real, cwd, depth)
        if real and os.path.dirname(real) in path_dirs():
            return check_segment_words([name] + args, cwd, depth, raw)
        return ask("`%s`" % binary, "runs a file the guard can't check")
    if name == "curl":
        if any(re.search(r"X-Amz-Signature=|[?&]Signature=|sig=", a) for a in args):
            return ask("`curl` to a signed URL", "a presigned URL can act with someone's credentials")
        auth = any(a.split("=", 1)[0] in {"-H", "--header"} and (re.search(
            r"authorization|x-api-key|token|cookie", a + " " + (args[k + 1] if k + 1 < len(args) else ""), re.I)
            or any(re.search(r"\$\{?%s\b" % n, args[k + 1] if k + 1 < len(args) else a) for n in HEADER_VARS))
            for k, a in enumerate(args))
        for k, a in enumerate(args):
            f = a.split("=", 1)[0]
            if auth and (f in {"-v", "--verbose", "--trace", "--trace-ascii", "--libcurl"} or
                         re.fullmatch(r"-[a-zA-Z]*v[a-zA-Z]*", a)):
                return secret("`curl %s` with an auth header" % f, "prints the token in the request headers")
            if f in {"-X", "--request"} or (a.startswith("-X") and len(a) > 2):
                method = a[2:] if a.startswith("-X") and len(a) > 2 else (
                    a.split("=", 1)[1] if "=" in a else (args[k + 1] if k + 1 < len(args) else ""))
                if method.upper() not in {"GET", "HEAD"}:
                    return ask("`curl -X %s`" % method, "can change something through a remote API")
            if f in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "--json",
                     "-T", "--upload-file", "--aws-sigv4", "-u", "--user", "-K", "--config", "--oauth2-bearer"}:
                return ask("`curl %s`" % f, "sends data, credentials or a signed request")
            if f in {"-o", "--output"} and k + 1 < len(args) and is_protected(args[k + 1], cwd):
                return ask("`curl -o %s`" % args[k + 1], "writes a protected path")
        if auth:  # a read: but a token sent to a host the project doesn't use could leak it (zero trust)
            hosts = {m.group(1).lower() for a in args for m in [re.match(r"^https://([A-Za-z0-9.-]+)(?::\d+)?(?:[/?#]|$)", a)]
                     if m}
            other = [a for a in args if re.match(r"^[a-z]+://", a, re.I) and not a.lower().startswith("https://")]
            unknown = sorted(h for h in hosts if not api_host_ok(h, cwd))
            if other or not hosts or unknown:
                return ask("`curl` with an auth header to `%s`" % (", ".join(unknown) or "a URL the guard can't read"),
                           "sends a token to a host that isn't a known provider API or a host in this project's .env")
        return None
    if name == "wget":
        if any(a.startswith(("--post", "--method", "--body")) for a in args):
            return ask("`wget` with a request body", "can change something through a remote API")
        return None
    if name in {"sed", "gsed"}:
        inplace = any(a.startswith(("-i", "--in-place")) for a in args)
        plain = [a for a in args if not a.startswith("-") and a != ""]
        has_e = any(a in {"-e", "--expression", "-f", "--file"} for a in args)
        files = [a for a in (plain if has_e else plain[1:]) if a not in
                 {args[k + 1] for k, x in enumerate(args[:-1]) if x in {"-e", "--expression"}}]
        if any(re.search(r"(^|[;{}\n])\s*[0-9,$/!]*\s*[wWe]\b|/[gpIiM0-9]*[we](\s|;|$)", a) for a in args):
            return ask("`sed` script with w or e", "can write files or run commands")
        if inplace and any(is_protected(f, cwd) for f in files):
            return ask("`sed -i` on a protected file", "changes the guard, its settings or a protected file")
        return None
    if name in {"kubescape", "prowler", "jscpd"}:
        outs = [args[k + 1] for k, a in enumerate(args[:-1]) if a in {"-o", "--output", "--output-directory"}]
        outs += [a.split("=", 1)[1] for a in args if a.startswith(("--output=", "--output-directory="))]
        if any(is_protected(o, cwd) for o in outs):
            return ask("`%s` writing into a protected path" % name, "changes the guard, its settings or a protected file")
    if name == "ifconfig":
        plain = [a for a in args if not a.startswith("-")]
        if set(args) - set(plain) <= {"-a", "-l", "-L", "-u", "-d", "-v"} and len(plain) <= 1:
            return None
        return ask("`ifconfig %s`" % " ".join(args), "changes a network interface")
    if name == "kubescape":
        sub = next((a for a in args if not a.startswith("-")), "")
        if "--show-secrets" in args:
            return secret("`kubescape --show-secrets`", "prints secret values")
        if sub not in {"scan", "list", "version", "diff", "help", ""}:
            return ask("`kubescape %s`" % sub, "changes files, images, the cluster or the tool itself")
        sent = [a for a in args if a.split("=", 1)[0] in {"--submit", "--account", "--access-key", "--server"}]
        if sent:
            return ask("`kubescape %s`" % sent[0], "sends the scan results to an outside service")
        return None
    if name == "prowler":
        risky = {"--fixer": "changes cloud resources", "--security-hub": "writes findings into Security Hub",
                 "-S": "writes findings into Security Hub", "--send-sh-only-fails": "writes findings into Security Hub",
                 "--output-bucket": "writes to a cloud bucket", "-B": "writes to a cloud bucket",
                 "--output-bucket-no-assume": "writes to a cloud bucket", "-D": "writes to a cloud bucket",
                 "--push-to-cloud": "sends the results to an outside service",
                 "--slack": "sends the results to Slack", "--shodan": "sends your IPs to Shodan",
                 "--scan-secrets-validate": "tries found secrets against live services"}
        hit = next((a.split("=", 1)[0] for a in args if a.split("=", 1)[0] in risky), None)
        return ask("`prowler %s`" % hit, risky[hit]) if hit else None
    if name in {"zizmor", "tflint"}:
        hit = next((a.split("=", 1)[0] for a in args if a.split("=", 1)[0] in {"--fix", "--init"}), None)
        return ask("`%s %s`" % (name, hit), "changes files or downloads plugins") if hit else None
    if name in {"awk", "gawk", "nawk"}:
        prog, k = None, 0
        while k < len(args):
            a = args[k]
            if a in {"-F", "-v"}:
                k += 2
                continue
            if a in {"-f", "--file"} or a.startswith("-f") and not a.startswith("-F"):
                return ask("`awk -f` program file", "can run commands or write files")
            if not a.startswith("-"):
                prog = a
                break
            k += 1
        prog = awk_code_only(prog or "")
        if re.search(r"system|getline|(?<!\|)\|(?!\|)", prog) or re.search(r"print[f]?[^;{}<>=]*>(?!=)", prog):
            return ask("`awk` program", "can run commands or write files")
        return None
    if name == "find":
        roots = []
        for a in args:
            if a.startswith(("-", "(", "!")):
                break
            roots.append(a)
        if "-delete" in args and any(outside_project(r, cwd) or is_protected(r, cwd) for r in roots or ["."]):
            return ask("`find -delete`", "deletes files outside the project or in a protected path")
        top = {"/", os.path.realpath(HOME), os.path.realpath(repo_root(cwd))}
        if "-delete" in args and not {"-name", "-iname", "-path", "-ipath", "-regex", "-newer", "-mtime", "-mmin",
                                      "-empty"} & set(args) and any(resolve(r, cwd) in top for r in roots or ["."]):
            return ask("`find -delete` on the whole repo or home", "would delete the repo, home or a parent of it")
        bad = {a for a in args if a in REMOTE_DENY_FLAGS["find"] - {"-exec", "-execdir", "-ok", "-okdir", "-delete"}}
        if bad:
            return ask("`find %s`" % sorted(bad)[0], "writes a file")
        hit = None
        for k, a in enumerate(args):  # -exec cmd ... ; : the command is checked like any other
            if a in {"-exec", "-execdir", "-ok", "-okdir"}:
                end = next((j for j in range(k + 1, len(args)) if args[j] in {";", "+", "\\;"}), len(args))
                inner = [w for w in args[k + 1:end] if w != "{}"] or [""]
                h = check_segment_words(inner, cwd, depth + 1, " ".join(inner)) if inner[0] else \
                    ask("`find -exec`", "runs nothing the guard can read")
                if inner[0] in DELETERS and any(outside_project(r, cwd) or is_protected(r, cwd) for r in roots or ["."]):
                    h = ask("`find -exec %s`" % inner[0], "deletes files outside the project or in a protected path")
                hit = worse(hit, h)
        return hit
    if name == "xargs":
        k = 0
        while k < len(args) and args[k].startswith("-"):
            k += 2 if args[k] in {"-P", "-n", "-I", "-L", "-s", "-d", "-E", "-a", "--max-procs", "--max-args",
                                  "--delimiter", "--arg-file"} else 1
        return check_segment_words(args[k:], cwd, depth, raw) if args[k:] else None
    if name == "scutil":
        return None if args[:1] in (["--dns"], ["--proxy"], ["--nwi"], ["--get"], ["-r"]) else ask(
            "`scutil %s`" % " ".join(args[:1]), "can change system network settings")
    if name == "date" and bundled(args, {"-s", "--set"}):
        return ask("`date -s`", "sets the clock")
    if name == "nc" and not bundled(args, {"-z"}):
        return ask("`nc`", "can send data to another host")
    if name in {"systemctl", "journalctl", "dmesg"}:
        return remote_segment([name] + args) and ask("`%s %s`" % (name, " ".join(args[:2])), "changes services")
    if name == "ssh-keygen" and bundled(args, {"-R", "-f"}) and not bundled(args, {"-L", "-l", "-y"}):
        return ask("`ssh-keygen`", "writes keys or known_hosts")
    if name in WRITERS:
        targets = [a for a in args if not a.startswith("-")]
        for t in targets:
            if TEST_MODE and resolve(t, cwd) is None:
                continue  # a test cleaning up its own temp folder, named by a variable
            if name in DELETERS and re.search(r"(^|/)__pycache__/?$|\.pyc$", t) and "$" not in t:
                continue  # python rebuilds its cache; deleting it changes nothing the guard runs
            if is_protected(t, cwd):
                return ask("`%s` on `%s`" % (name, t), "changes the guard, its settings or a protected file")
        if name in DELETERS | {"mv"}:
            for t in (targets if name != "mv" else targets[:-1]):
                if outside_project(t, cwd):
                    return ask("`%s %s`" % (name, t), "deletes or moves files outside the project")
        if name == "rm" and bundled(args, {"-r", "-R", "--recursive"}):
            for t in [v for t in targets for v in (loop_values(t) or [t])]:
                real = resolve(t, cwd)
                if real is None and TEST_MODE:
                    continue  # a test removing its own temp folder
                if real is None or real in {"/", os.path.realpath(HOME), os.path.realpath(repo_root(cwd))} \
                        or os.path.realpath(cwd).startswith(real + os.sep):
                    return ask("`rm -r %s`" % t, "would delete the repo, home or a parent of it")
        return None
    if name in READERS:
        return None
    if name in PKG_MANAGERS:
        verbs = positional(args)
        if not verbs or verbs[0] in PKG_READ or args in (["--version"], ["-v"], ["-h"], ["--help"]):
            return None
        return ask("`%s %s`" % (name, verbs[0]), "installs or removes software on this machine")
    if name == "perl":
        k = next((k for k, a in enumerate(args[:-1]) if a == "-e" or re.fullmatch(r"-[0lnpi]*e", a)), None)
        code = args[k + 1] if k is not None else ""
        edits = re.sub(r"(?:^|(?<=;))\s*(?:s|tr|y)([^\w\s{(\[<])(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[gimsxrc]*\s*(?:;|$)",
                       "", code, flags=re.S)
        if k is not None and code and not edits.strip() and sum(1 for a in args if a.startswith("-") and "e" in a) == 1:
            files = [a for j, a in enumerate(args) if j != k + 1 and not a.startswith("-")]
            if any(is_protected(f, cwd) for f in files):
                return ask("`perl -i` on a protected file", "changes the guard, its settings or a protected file")
            return None  # only s/// and tr///, without the e flag: text substitution, like sed
    if name in {"perl", "ruby"}:
        code = " ".join(args)
        if re.search(r"\bsystem\b|\bexec\b|`|\bqx\b|\bspawn\b|\bopen\s*\(?[^)]*\||%x|\bIO\.popen|\bunlink\b|"
                     r"\brmtree\b|\bSocket\b|LWP|Net::|require|\buse\s|-M", code):
            return ask("`%s` code" % name, "runs programs, deletes files or reaches the network")
        return None
    if name == "tmux" and positional(args)[:1] in (["ls"], ["list-sessions"], ["list-windows"], ["list-panes"],
                                                     ["capture-pane"], ["display-message"], ["has-session"]):
        return None
    if name == "act" and (bundled(args, {"-n", "--dryrun", "-l", "--list", "-g", "--graph", "--validate"})
                           or any(a.startswith("--dryrun") for a in args)):
        return None  # parses the workflows, starts nothing
    if name in INFRA_TOOLS and INFRA_TOOLS[name] != _REMOTE:
        if args in (["--version"], ["version"], ["-h"], ["--help"], ["help"]):
            return None
        return ask("`%s`" % name, INFRA_TOOLS[name])
    return check_by_shape(name, args, cwd)


MKTEMP_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)=[\"']?\$\(\s*mktemp\b[^)]*\)")
STATUS_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)=\$\?")
KNOWN = {}  # variables set to literals earlier in the command being checked; inherited by sh -c / xargs
HEADER_VARS = set()  # NAME="...$(read a project secret)..." used only as `curl -H "$NAME"`: a token header
LOOPS = {}  # `for NAME in a b c` over literal words, NAME never set another way: the values NAME takes
FOR_LOOP = re.compile(r"\bfor\s+([A-Za-z_]\w*)\s+in\s+([^;\n]*?)\s*(?:;|\n)\s*do\b")
CASE_PATTERNS = re.compile(r"(\bin|;;&?|;&)(\s+)\(?([^\s()|;&'\"`$]+(?:\s*\|\s*[^\s()|;&'\"`$]+)*)\)")
FUNCS = set()  # shell functions defined in the text being checked; their bodies are checked where defined
FUNC_DEF = re.compile(r"(?m)(?:^|[;&|{(]|\bthen|\bdo|\belse)\s*(?:function\s+([A-Za-z_][\w-]*)|([A-Za-z_][\w-]*)\s*\(\s*\))")
# NAME=literal at the top level of a command line, so `$(...)` checked before the assignment still sees its value
TOP_ASSIGN = re.compile(r"(?m)(?:^|[;&\n])\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|`$()'\"<>]+)(?=\s*(?:;|&&|\n|$))")


# `set -a; . ./.env`: the project's own .env is loaded, so its base URLs are known values
ENV_SOURCED = re.compile(r"(?:^|[;&|\n(]|\bthen|\bdo)\s*(?:\.|source)\s+(?:\./)?\.env(?=[\s;&|)]|$)")


def env_base_urls(cwd):
    """NAME -> https://host[:port] from the project's .env. Only bare base URLs: a URL with a path or query may
    carry a secret (a webhook key), and these values are substituted into the command being checked."""
    text = read_text(os.path.join(repo_root(cwd), ".env")) or ""
    return {m.group(1): m.group(2) for m in re.finditer(
        r"(?m)^\s*(?:export\s+)?([A-Za-z_]\w*)=['\"]?(https://[A-Za-z0-9.-]+(?::\d+)?)/?['\"]?\s*$", text)}


def path_arg_functions(command):
    """`get() { curl "$G$1"; }; get /api/x; get /api/y`: when every call passes a literal path starting with `/`,
    `$1` in the body is that path, so it can't change the host. Returns the command with `$1` rewritten to a path."""
    if re.search(r"(?:^|[;&|\n(]|\bthen|\bdo|\bexec)\s*\"?\$|\$[@*]|\beval\b", command):
        return command  # a computed command could call the function with anything
    for m in re.finditer(r"(?m)(?:^|[;&|\n])\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\s*\)\s*\{", command):
        name, start, depth, i = m.group(1), m.end(), 1, m.end()
        while i < len(command) and depth:
            if command.startswith("${", i):
                i = command.index("}", i) + 1 if "}" in command[i:] else len(command)
                continue
            depth += {"{": 1, "}": -1}.get(command[i], 0)
            i += 1
        body, rest = command[start:i - 1], command[:m.start()] + " " + command[i:]
        if not re.search(r"\$\{?1\b", body):
            continue
        firsts = [a.strip("\"'") for a in re.findall(
            r"(?:^|[;&|\n(]|\bthen|\bdo)\s*%s(?![\w-])(?:\s+(\"[^\"$`\\]*\"|'[^']*'|[^\s;&|<>\"'`$\\]+))?"
            % re.escape(name), rest, re.M)]
        if len(firsts) != len(re.findall(r"(?<![\w$-])%s(?![\w-])" % re.escape(name), rest)):
            continue  # named somewhere other than at the start of a command (an argument, a string): can't tell
        if firsts and all(f.startswith("/") for f in firsts):
            command = command[:start] + re.sub(r"\$\{1\}|\$1(?!\d)", "/__path__", body) + command[i - 1:]
    return command


def substitute(text, known):
    for name, value in known.items():
        text = re.sub(r"\$\{%s\}|\$%s(?![A-Za-z0-9_])" % (name, name), lambda _m: value, text)
    return text


TEST_MODE = False  # inside a test file: tests mock tools by changing PATH, which is tolerated there


def check_command(command, cwd, depth=0, raw=None, test_mode=None):
    """The worst decision over every part of a shell command line, or None when all of it is safe."""
    global KNOWN, FUNCS, TEST_MODE, LOOPS, HEADER_VARS
    outer_test, outer_loops, outer_headers = TEST_MODE, LOOPS, HEADER_VARS
    raw_defs = command
    if test_mode is not None:
        TEST_MODE = test_mode
    command = command.replace("\\\n", " ")  # line continuations
    if re.search(r"\bcase\b", command):  # `a|b)` case patterns are words to match, not commands to run
        command = CASE_PATTERNS.sub(r"\1\2", command)
    raw = raw if raw is not None else command
    command = path_arg_functions(command)
    # `name(){ body; }` mid-line: check the body as a { ...; } group; calls to `name` are then known (FUNCS)
    command = re.sub(r"(^|[;&|\n]\s*)(?:function\s+)?[A-Za-z_][\w-]*\s*\(\s*\)\s*\{", r"\1{ ", command)
    outer, known = KNOWN, dict(KNOWN)
    outer_funcs = FUNCS
    FUNCS = FUNCS | {a or b for a, b in FUNC_DEF.findall(raw_defs)}
    tops = TOP_ASSIGN.findall(command)
    names = [n for n, _ in tops]
    for n, v in tops:
        if names.count(n) == 1 and n not in known and not DANGEROUS_ENV.match(n):
            known[n] = v  # assigned once, to a literal: the same value wherever it's used
    if ENV_SOURCED.search(command):
        for n, v in env_base_urls(cwd).items():
            if n not in names and n not in known and not re.search(r"(?:^|[\s;&|(])%s\+?=" % n, command):
                known[n] = v
    for m in MKTEMP_ASSIGN.finditer(command):
        known[m.group(1)] = "/tmp/__mktemp__"
    for m in STATUS_ASSIGN.finditer(command):
        known[m.group(1)] = "0"
    loops = dict(LOOPS)
    for m in FOR_LOOP.finditer(command):
        n = m.group(1)
        try:
            values = shlex.split(m.group(2))
        except ValueError:
            continue
        reset = re.search(r"(?:^|[\s;&|(])%s\+?=|\b(read|getopts|mapfile|readarray|select)\b[^;&|\n]*\b%s\b"
                          % (n, n), command)
        if not values or reset or n in KNOWN or any(re.search(r"[$`*?\[{]|__SUBST__", v) for v in values):
            loops[n] = None  # set some other way too: its value can't be known
        elif loops.get(n, ()) is not None:
            loops[n] = loops.get(n, []) + values  # two loops over the same name: either list's values
    headers = set(HEADER_VARS)
    if not re.search(r"\bset\s+-[a-z]*x|xtrace|\bBASH_XTRACEFD\b", command):
        for m in re.finditer(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=\"[^\"$]*\$\(", command):
            n = m.group(1)
            uses = re.findall(r"(.{0,12})\$\{?%s\b\}?" % n, command)
            if uses and all(re.search(r"(-H|--header)\s+\"[^\"]*$", u) for u in uses) and \
                    len(re.findall(r"(?:^|[\s;&|(])%s\+?=" % n, command)) == 1:
                headers.add(n)
    try:
        HEADER_VARS = headers
        LOOPS = {n: v for n, v in loops.items() if v}
        KNOWN = known
        return _check_command(command, cwd, depth, raw, known)
    finally:
        KNOWN, FUNCS, TEST_MODE, LOOPS, HEADER_VARS = outer, outer_funcs, outer_test, outer_loops, outer_headers


def _check_command(command, cwd, depth, raw, known):
    if depth > MAX_DEPTH:
        return ask("a deeply nested command", "is nested too deep to check")
    try:
        stripped, bodies = extract_heredocs(command)
    except ValueError as exc:
        return ask("an unparseable heredoc", str(exc))
    hit = None
    for _key, (body, quoted) in bodies.items():
        if not quoted:
            try:
                _segs, subs = split_shell(body)
            except ValueError:
                return ask("a heredoc body", "has unbalanced quotes or substitutions")
            for inner in subs:
                hit = worse(hit, check_command(inner, cwd, depth + 1, raw))
    try:
        segments, subs = split_shell(stripped)
    except ValueError as exc:
        return ask("an unparseable command", "could not be parsed (%s)" % exc)
    for inner in subs:
        h = as_use(check_command(inner, cwd, depth + 1, raw), cwd)
        if h and h[1] == USE_SECRET and any(re.search(r"(?:^|[\s;&|(])%s=\"[^\"$]*\$\(%s\)" % (n, re.escape(inner)),
                                                      raw) for n in HEADER_VARS):
            h = None  # the token only goes into a curl header; curl checks where it is sent
        hit = worse(hit, h)
        if hit and hit[2] == "deny":
            return hit
    for seg in segments:
        seg = substitute(seg, known)
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = []
        assigns = toks[1:] if toks[:1] in (["export"], ["local"], ["readonly"]) else toks
        if assigns and all(ASSIGNMENT.match(t) for t in assigns):
            for t in assigns:
                n, _, v = ASSIGNMENT.match(t).groups()
                if not re.search(r"[$`]|__SUBST__", v) and not DANGEROUS_ENV.match(n):
                    known[n] = v
        if toks[:1] == ["cd"]:  # follow cd so later relative paths resolve where the shell will be
            target = toks[1] if len(toks) > 1 else HOME
            real = resolve(target, cwd)
            if real and os.path.isdir(real):
                cwd = real
            continue
        hit = worse(hit, check_segment(seg, bodies, cwd, depth, raw))
        if hit and hit[2] == "deny":
            return hit
    return hit


# --------------------------------------------------------------------------------------------------------------
# Entry point.
# --------------------------------------------------------------------------------------------------------------
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}


def classify(payload):
    """(decision, reason) for a PreToolUse payload; decision is "ask" or "deny", or None to let it run."""
    cwd = payload.get("cwd") or project_dir(payload)
    tool = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return "deny", "the tool input could not be inspected"
    if tool in EDIT_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if path and is_protected(path, cwd):
            return "ask", "Editing `%s` changes the guard, its settings or a file that controls what commands do." % path
        return None
    if tool in READ_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or "")
        pattern = str(tool_input.get("glob") or "")
        samples = (".env", ".env.local", ".secret", "x.tfstate", "id_rsa", "x.pem", "credentials.json", ".envrc")
        if (path and is_secret(path, cwd)) or (pattern and tool != "Glob" and
                                               any(fnmatch.fnmatch(x, os.path.basename(pattern)) for x in samples)):
            return "deny", "Reading `%s` would put a secret in the conversation." % (path or pattern)
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    hit = check_command(command, cwd)
    if not hit:
        return None
    what, why, level = hit
    if level == "ask" and any(p.search(command.strip()) for p in project_allow(payload)):
        return None  # the user listed this command as trusted (.claude/goodbehavior/guard-allow.txt)
    if level == "ask":
        token = consent_token(command, cwd)
        if consent_given(payload, token, command):
            return "consented", "the user said yes to [run:%s]" % token
    if level == "deny":
        return "deny", "BLOCKED: %s %s. Use the value without printing it, or ask the user to look." % (what, why)
    if level == "user":
        return "deny", ("BLOCKED: %s %s. Claude never runs a load test, not even after a yes. Suggest it instead: "
                        "give the user the script, the exact command, which non-production host to point it at and "
                        "what to watch, and leave running it to them." % (what, why))
    return "ask", ("%s %s." % (what, why) + CONSENT_HOWTO.format(token=consent_token(command, cwd)))


def project_allow(payload):
    """Regexes (one per line, # comments) the user trusts in .claude/goodbehavior/guard-allow.txt. They can turn an
    ask into a run; secrets stay denied. The file sits in .claude/, so Claude can't edit it without asking."""
    path = os.path.join(project_dir(payload), ".claude", "goodbehavior", "guard-allow.txt")
    out = []
    for line in (read_text(path) or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                out.append(re.compile(line))
            except re.error:
                pass
    return out


import hashlib  # noqa: E402


def local_scripts(toks, cwd):
    """Local files a command segment would execute: `./x.sh`, `bash x.sh`, `python3 x.py`, `make -f x.mk`."""
    while toks and ASSIGNMENT.match(toks[0]):
        toks = toks[1:]
    if not toks:
        return []
    head = os.path.basename(toks[0])
    cands = [toks[0]] if "/" in toks[0] else []
    if head in SHELL_BINARIES | {"python", "python3", "node", "bats"}:
        cands += [t for t in toks[1:] if not t.startswith("-")][:1]
    if head in {"make", "gmake"}:
        cands += [os.path.join(cwd, "Makefile")]
    out = []
    for c in cands:
        real = resolve(c, cwd)
        if real and os.path.isfile(real):
            out.append(real)
    return out


def consent_token(command, cwd):
    """Ties a yes to this exact command and the current contents of any local script it runs."""
    h = hashlib.sha256(command.strip().encode())
    try:
        segs, _ = split_shell(extract_heredocs(command)[0])
    except ValueError:
        segs = []
    for seg in segs:
        try:
            toks = shlex.split(seg)
        except ValueError:
            continue
        for path in local_scripts(toks, cwd):
            h.update((read_text(path) or "").encode())
    return h.hexdigest()[:12]


def transcript_entries(payload):
    path = payload.get("transcript_path") or ""
    out = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def _blocks(entry):
    msg = entry.get("message") or {}
    content = msg.get("content")
    return content if isinstance(content, list) else []


def _is_human(entry):
    msg = entry.get("message") or {}
    if (entry.get("type") or msg.get("role")) != "user":
        return False
    content = msg.get("content")
    if isinstance(content, str):
        return bool(content.strip())
    return any(isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip() for b in content or [])


def consent_given(payload, token, command):
    """True when, since the user's last message, they answered "Yes…" to an AskUserQuestion carrying
    [run:<token>], and the command hasn't already run on that yes."""
    entries = transcript_entries(payload)
    last_human = max([i for i, e in enumerate(entries) if _is_human(e)] or [-1])
    asked, approved_at = {}, None
    for i, e in enumerate(entries[last_human + 1:], start=last_human + 1):
        for b in _blocks(e):
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "AskUserQuestion":
                inp = b.get("input") or {}
                qs = [q.get("question", "") for q in inp.get("questions", []) if isinstance(q, dict)]
                hidden = str((inp.get("metadata") or {}).get("source", "")) == "run:%s" % token
                # the token sits in the hidden metadata (one question per call) or, from older sessions, in the text
                hits = qs[:1] if hidden and len(qs) == 1 else [q for q in qs if "[run:%s]" % token in q]
                if hits:
                    asked[b.get("id")] = hits
            if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("tool_use_id") in asked:
                answers = (e.get("toolUseResult") or {}).get("answers") or {}
                if any(str(answers.get(q, "")).strip().lower().startswith("yes") for q in asked[b.get("tool_use_id")]):
                    approved_at = i
    if approved_at is None:
        return False
    runs = sum(1 for e in entries[approved_at + 1:] for b in _blocks(e)
               if isinstance(b, dict) and b.get("type") == "tool_use"
               and str((b.get("input") or {}).get("command", "")).strip() == command.strip())
    return runs <= 1  # the call being checked may already be in the transcript; a second run needs a new yes


CONSENT_HOWTO = (" To run it, ask the user with AskUserQuestion, one question per call, with metadata "
                 "{{\"source\": \"run:{token}\"}} (hidden from the user; don't put it in the question text). First, in "
                 "your normal reply text, explain in plain words what the command or script does, why it's needed, "
                 "what could break and how to undo it. Keep the question itself to one short line (it shows large and "
                 "bold), for example \"Run the Grafana alert fix script?\", and offer the options \"Yes, run it\" and "
                 "\"No\" with one-line descriptions. If they choose Yes, run the exact same command again, "
                 "unchanged. If AskUserQuestion isn't available (a non-interactive run), explain it and ask the user "
                 "to run it themselves.")


BYPASS_NOTE = (" (Permissions are bypassed in this session, so the permission prompt can't be used; ask with "
               "AskUserQuestion as above.)")


def log(payload, decision, reason):
    try:
        path = os.path.join(project_dir(payload), ".claude", "goodbehavior", "guard.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
        with open(path, "a") as f:
            f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": payload.get("tool_name"),
                                "decision": decision, "mode": payload.get("permission_mode"),
                                "input": str(ti.get("command") or ti.get("file_path") or ti.get("path") or "")[:300],
                                "reason": reason[:300]}) + "\n")
    except OSError:
        pass


def decide(payload):
    """Fail-closed wrapper: (decision, reason) or None. A crash denies."""
    try:
        result = classify(payload)
    except Exception as exc:  # noqa: BLE001 — fail closed: a crash must never let a command through
        result = ("deny", "The guard crashed (%s: %s), so this could not be checked." % (type(exc).__name__, exc))
    if result is None:
        return None
    decision, reason = result
    if decision == "consented":
        log(payload, "consented", reason)
        return None
    if decision == "ask" and payload.get("permission_mode") == "bypassPermissions":
        decision, reason = "deny", reason + BYPASS_NOTE
    log(payload, decision, reason)
    return decision, "GoodBehavior guard: " + reason


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        payload = None
    result = ("deny", "GoodBehavior guard: the tool payload could not be read.") if not isinstance(payload, dict) \
        else decide(payload)
    if result:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": result[0],
                                          "permissionDecisionReason": result[1]}}, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
