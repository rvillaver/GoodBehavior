---
name: devops
use-when: the output is LIVE INFRASTRUCTURE checked against its real state — cloud or on-prem resources, IaC (Terraform/OpenTofu, Bicep, CloudFormation, Pulumi, Ansible), Kubernetes/Helm, networking, CI/CD pipelines, platform config
truth-source: the live environment (provider APIs, real network paths, the state the tooling reads back)
---

- **consumer:** the workload or operator that depends on the infrastructure: an app that needs to reach its database,
  a user hitting an endpoint, an on-call engineer running a restore.
- **the-real-thing:** the resources as they exist in the target environment after apply, read back from the provider
  (or the hosts, for on-prem). The code, the plan and the console form you filled in do not count.
- **verify:** with the user's consent (see below), apply to a non-production environment first, then exercise the
  infrastructure from the consumer's network position: resolve the DNS name, call the endpoint, connect to the
  database from the app's subnet, assume the role and try the denied action, fail over, restore the backup. Then
  re-run the plan and confirm it shows no changes (no drift, no perpetual diff).
- **evidence:** the reviewed plan, the apply output, a post-apply plan showing no changes, and the probe output from
  the consumer's position (`curl`, `dig`, `nc`, a CLI `describe`/`get` of the resource, a restore log). Each piece
  names the environment and account/subscription/project it came from.
- **verify anti-patterns:** "`validate`/`lint` passed"; "the plan looks right" with nothing applied; apply succeeded
  but nothing probed it; probing from inside the same host or with admin credentials, so a firewall or IAM gap stays
  hidden; a backup that exists but was never restored; verified in dev, claimed for prod; a console change that never
  made it into code.
- **audit lenses:** run each as its own pass, then compare. **Wiring:** does it work from the consumer's position
  (reachable, resolvable, allowed)? **Security:** the attack surface, judged against today's automated attacks (rules
  and probes in `devops/baseline.md`, Security and attack surface, and `devops/kubernetes.md` for clusters; see
  "Security findings" below; if a cluster has no secrets manager, suggest OpenBao, per `devops/kubernetes.md`).
  **Reliability:** single points of failure, backups restore-tested, failover. **Drift:** code vs state vs live
  resource. **Cost:** over-provisioned, under-provisioned, redundancy that the requirements don't need, wrong pricing
  model, storage tier, idle resources, data transfer (rules and probes in `devops/baseline.md`, Cost). Write every
  cost finding with all five parts of "Cost in every proposal": now, change, saving, performance and risk, way back. A
  cost cut that weakens reliability is a contradiction between lenses: flag it, don't pick silently. **Code:** the
  Terraform, pipelines, scripts and charts themselves: secrets in code and git history, misconfigurations, unsafe
  pipelines, lint, copy-paste and dead code (rules and probes in `devops/baseline.md`, Code, plus `devops/terraform.md`,
  `devops/shell.md`, `devops/helm.md`). Security, cost and code also each get their own checklist batch: see "Audit
  coverage" below.
- **pause points:** **every** change to infrastructure, in **any** environment, dev included: an apply, destroy or
  import; a state edit (`state rm`/`mv`/`push`); a CLI call that creates, updates, deletes, restarts or scales
  something; a `kubectl`/`helm` write; a playbook run; a change made over SSH. Infrastructure has no `git reset`. A
  deleted database, a replaced disk or a wrong firewall rule can't be undone by reverting code. So propose first and
  wait for a clear yes, every time, even under standing-proceed. A yes covers only the commands it was given for.

## Security findings

Automated attacks are cheap now: bots scan every public address within minutes, credential stuffing and DDoS are
rented by the hour, and AI writes working exploits fast. Treat every public endpoint as under attack today. In every
audit, check the attack surface (exposure, DDoS and rate limits, bots, injection, identities, secrets, patching,
detection) and write each security finding so a non-expert can act on it:
- **Risk:** what an attacker could do, in one plain sentence ("anyone on the internet can try passwords against the
  database").
- **How likely:** is it exposed to the internet, is it a known, scanned-for weakness, is it already being probed
  (check the logs).
- **Impact:** what happens to data, money, users or uptime if it's used.
- **Fix:** the change that closes it, and what it costs or breaks.
- **Evidence:** the probe output that shows the gap.
Rank by likely impact, worst first. Never call something "secure"; say which checks passed and what was not checked.

## Audit coverage: security, cost and code

Area batches (network, data, compute…) find what their area shows; they miss whatever nobody went looking for. So
every devops audit also runs three checklist batches of its own, after the area batches: **security**, **cost** and
**code**. "No findings" from a pass that only looked at a few things is not a clean result.

1. **Build the checklist from the installed guides**, so every rule gets a row. Run this from the project root and
   paste the output into the batch file (`docs/audit/NN-security.md`, `NN-cost.md`, `NN-code.md`):
   ```sh
   awk 'FNR==1{g=FILENAME;sub(".*/","",g);sub(/\.md$/,"",g);n=0} /^## /{s=substr($0,4)} /^- \*\*rule:\*\*/{n++;k="";r=substr($0,13);gsub(/\|/,"/",r); if(g~/^(terraform|shell)$/&&s!~/Before running/||s~/IaC|CI\/CD|^Code$|Charts|Delivery/)k="code"; else if(s~/Security|Secrets|identity|Networking|Access|Supply chain/)k="security"; else if(s~/Cost/)k="cost"; if(k!="")printf "| %s | %s-%d | %s | %s | | |\n",k,g,n,s,r}' .claude/goodbehavior/profiles/devops/*.md
   ```
   Columns: lens, rule ID, section, rule, **result**, **evidence**. Every row gets one result: **pass** (with the
   probe output), **finding** (with its ID), **not checked** (and why: no access, tool missing, pause point not
   approved, guard stopped it), or **n/a** (and why). No blank rows.
2. **Run the broad scanners too**, because a checklist only covers what it lists. All are read-only:
   - Code: `gitleaks`, `trivy config`, `checkov`, `tflint`, `shellcheck`, `zizmor`/`actionlint`, `jscpd` (commands in
     `devops/baseline.md`, Code).
   - Cloud account: Prowler for AWS, GCP and Azure (`devops/aws.md`, `devops/gcp.md`, `devops/azure.md`), or the
     provider's own security standard.
   - Clusters: `trivy k8s`, `kubescape` or Prowler (`devops/kubernetes.md`).
   - Images in use: `trivy image`.
   **A scanner that isn't installed: ask the user before installing it**, then run it. Check first
   (`command -v <tool>`), list every missing tool in one question (AskUserQuestion), and say for each: what it
   checks, that it only reads, the exact install command (`brew install gitleaks actionlint zizmor kubescape`,
   `go install github.com/terraform-linters/tflint@v0.58.1` (tflint is not in Homebrew),
   `pipx install --python python3.12 prowler` (Prowler fails on Python 3.14), `npm install -g jscpd@4.0.5`) and where
   it installs. Offer "Yes, install all", "Pick which" and "No".
   Install only what the user said yes to. A tool the user declined is a **not checked** row with its install
   command, never a silent skip, and never a pass.
3. **Cost uses real numbers.** Read the last full month's bill by service (Cost Explorer, `doctl invoice list`, the
   portal) and 14–30 days of usage per resource. End the cost batch with a savings table, biggest first: item, now,
   change, saving per month, risk. If the bill can't be read, say so at the top: every price is then an estimate.
4. **Open each batch with a verdict in plain words**, for example: "Security: 7 risks found (2 high). 31 of 57 checks
   passed, 12 not checked." or "Cost: about $410/mo could be saved; the bill was read for September." Never write
   "secure", "optimized" or "clean"; give the counts and what was not checked.
5. **The audit's final report to the user always has three short parts, security, cost and code**, each with its
   counts and its worst three findings, even when a count is zero. Don't let reliability P0s crowd them out.

## Secrets

- Credentials (passwords, tokens, API keys, private keys) go in a `.secret` file (or a `.secret/` folder) at the repo
  root: listed in `.gitignore`, mode `600`, loaded by the tooling (for example `set -a; . ./.secret; set +a` or a
  Makefile `-include .secret`). Never in code, `*.tfvars`, state outputs, CI logs or chat. Shared or production
  secrets belong in the platform's secret manager; `.secret` holds the local copy a tool needs.
- **Never read** `.secret`, `.env` or credential files, and never run a command that prints a secret value. The guard
  denies both. To change a value, write it without reading the file (append a line, or `sed -i` a known key), or ask
  the user to do it. Use secrets by reference (environment variables, secret-manager lookups), never by echoing them.
- Probe: `git check-ignore .secret .env` lists both; `stat -c '%a' .secret` (Linux) or `stat -f '%Lp' .secret`
  (macOS) prints `600`; `gitleaks detect` finds nothing in the repo or its history.

## Credentials and profiles: a suggestion

We suggest keeping the values that pick an account or a tool in the project's `.env` (loaded by the Makefile,
`direnv` or `set -a; . ./.env; set +a`) rather than typing them in front of commands: `AWS_PROFILE`, `AWS_REGION`,
`ARM_SUBSCRIPTION_ID`, `CLOUDSDK_CORE_PROJECT`, `TF_VAR_*` that aren't secret, and so on. Every command then runs
against the same, visible account, and a one-off `AWS_PROFILE=admin aws ...` stands out. Actual secrets go in
`.secret` (see Secrets). This is a suggestion; follow the project's own convention if it has one.

## The guard

`devops/guard.py` runs before every tool call (the done-gate hook hands each call to it). It works like a
default-deny guard with a softer default:
- **Runs** what it can show is read-only or local: cloud reads (`describe`, `list`, `get`), plans and tests,
  scanners, local git commits, local docker, SSM port-forward tunnels, `ssh -N -L` tunnels, and ssh commands whose
  every part reads (logs, status, files), pipes included. It reads `make` recipes (prerequisites, variables, `.env`,
  recursive make), scripts and the scripts they source, package scripts and inline Python before deciding.
- **Asks you right away**, saying what it found and why, for anything that changes something or that it can't show
  is safe: infrastructure writes, remote changes over ssh, unknown programs, `eval`, unparseable lines, edits to
  `.claude/`, `.mcp.json`, the lock file or scanner config.
- **Denies** anything that would show a secret (credential files, `.env`/`.secret`, secret-manager reads, token
  printers, state dumps, `docker inspect` without `--format`), and anything it crashed on. With permissions bypassed,
  every ask becomes a deny.
- Logs every ask and deny to `.claude/goodbehavior/guard.log` (we suggest adding it to `.gitignore`).
- **Trusted commands:** list regexes, one per line, in `.claude/goodbehavior/guard-allow.txt` for commands this
  project trusts (for example `^make test_` for local test targets). A match turns an ask into a run; it never lifts a
  deny, so secrets stay protected. The file is under `.claude/`, so Claude can't add to it without asking, and
  `/update-goodbehavior` never touches it.
It is a speed bump, not a sandbox: the credential the session runs with is the real boundary.

## Running scripts and make targets

Assess the risk before running anything that wraps other commands (a script, a `make` target, inline code):
- Read it first. The guard reads it too, and asks when it finds a change or a secret.
- **Harmless** (it only reads, builds, tests, plans or prints non-secret output): run it.
- **Risky** (it changes infrastructure, deletes or overwrites data, or touches secrets): don't run it yet. Tell the
  user, in plain words, why it needs to run, what it will change, what could go wrong, and what it fixes. Then ask.

## Investigate before you change

Most infra damage comes from fixing the wrong thing fast. Before proposing any change:
- Find the actual cause with **read-only** commands: `plan`, `describe`, `show`, `get`, `list`, logs, `dig`, `curl`.
  Don't change anything "to see if it helps".
- Check the live state, not just the code. Code, state file and the real resource can disagree.
- Know what else depends on the thing you would touch: other apps, other teams, DNS, shared networks.
- If you can't find the cause, say so and list what you checked. A guess presented as a finding is worse than "I
  don't know yet".

## Propose, then ask

Before running anything that changes infrastructure, show the user this and wait for their answer:

1. **What I found:** the problem and its cause, with the command output that shows it.
2. **What I want to do:** the fix in plain words, then the exact commands or the plan output.
3. **Why it fixes it:** how this change removes the cause.
4. **What could go wrong:** what may break, go down or be deleted, for how long, and who would notice. Call out every
   destroy or replace in the plan by name.
5. **How to undo it:** the way back, or a plain "this can't be undone" (deleted data, replaced resources).
6. **Where it runs:** environment and account/subscription/project.
7. **Cost:** what this changes in the monthly bill, and any cheaper option with the same performance (see "Cost in
   every proposal" below).
8. **Your call:** ask with the question picker (AskUserQuestion), options **"Yes, run it"** and **"No"** (the user
   can always pick Other). No yes, no change.

**Running it after a yes.** When the guard stops a command, its message carries a token like `run:3f9c…`. Ask with
AskUserQuestion, one question per call, and put the token in the call's hidden `metadata` as
`{"source": "run:3f9c…"}`, never in the question text the user reads. Give the explanation above (for a script: what it is for and what each risky
step does). If the user picks "Yes, run it", run the exact same command again, unchanged: the guard finds the yes in
the session transcript and lets it run once. Don't hand the user a script to run themselves unless they ask for that.
A new message from the user, a second run, or any edit to the script after the yes needs a new yes. Secrets stay
denied whatever the answer.

## Cost in every proposal

Whenever you design, change or review infrastructure, look for the same performance at a lower cost, and say what
you found even when it wasn't asked. Each cost suggestion states:
- **Now:** what it costs today, from the bill or the provider's pricing page. Say which.
- **Change:** what you would change (size, tier, pricing model, schedule, removal).
- **Saving:** the estimated monthly saving. Label it an estimate and say how you got it.
- **Performance and risk:** what happens to speed, capacity and availability. Base sizing on real usage data (14 days
  or more), not a guess.
- **Way back:** how to undo it if performance drops.
Never remove redundancy that an availability requirement depends on without asking. Under-provisioning is also a
cost (slow responses, crashes, retries, extra replicas), so a bigger size can be the cheaper fix.

## Talk plainly

Assume the user is not an infrastructure expert. Many people now build with AI and never learned the terms.
- Use short sentences and everyday words. Explain a term the first time you need it ("a security group, which is the
  firewall for this server").
- Say what will happen to their app or users, not only what happens to the resource: "the site will be down for about
  2 minutes", "this deletes the old database and its data".
- No filler and no showing off. Say the finding, the fix, the risk, and the question.
- Never hide a risk inside jargon. If something is dangerous, say so in one plain sentence.

> Provider and workflow facets are confirmed during adoption: which clouds/on-prem platforms, the IaC tool and where
> its state lives, the environment ladder (dev → staging → prod), how credentials are obtained, and what "non-prod"
> means in this project.

**Guides** (in `devops/` next to this file; install only the ones that match): `baseline` has the cross-cloud rules,
each paired with its live probe (IaC and state, CI/CD, secrets and identity, networking, observability, backup/DR,
cost). It always comes with this profile. Then add one provider guide per platform in use (`aws`, `azure`, `gcp`,
`digitalocean`, `onprem`; each maps the baseline rules to that platform's services and CLI probes) and one tool guide
per IaC tool in use (`terraform`: safe plan and apply, state, environments, code; `shell`: writing and running scripts
safely; `kubernetes`: clusters, workloads and their attack
surface, OpenBao for secrets; `helm`: charts and releases).

## Done-gate questions

The done-gate hook asks these in place of its generic self-check when this profile is installed. Edit them freely.
`match:` lines (one regex each, any can match) list the commands that change infrastructure. For the done-gate, a
turn that ran one (or edited files) is a **change**, any other turn is an **investigation**. Without `guard.py`
installed, the hook also falls back to these lines, plus `### gate: secrets` and `### gate: protect`, as a simpler
text-matching guard. Add a line when you use a tool that isn't covered. `### gate: protect` lists files whose edits
always ask: the guard's hooks, settings and these rules. `claims:` adds conclusion phrases that count as a "done"
claim.

### gate: change
match: \b(terraform|tofu|terragrunt)\s+(.*\s)?(apply|destroy|import|taint|untaint|force-unlock|state\s+(rm|mv|push|replace-provider)|workspace\s+delete)\b
match: \b(pulumi\s+(up|destroy|refresh|import|state\s+delete)|cdk\s+(deploy|destroy))\b
match: \baws\s+\S+\s+(create|delete|update|put|modify|attach|detach|associate|disassociate|run|start|stop|terminate|reboot|restore|replace|authorize|revoke|register|deregister|enable|disable|set|tag|untag|rotate|failover|promote|copy|reset|cancel|purge|import|batch)-
match: \baws\s+(\S+\s+deploy\b|s3\s+(rm|mv|cp|sync|rb|mb)\b|s3api\s+(delete|put)-)
match: \baz\s+([\w-]+\s+)+(create|delete|update|set|add|remove|start|stop|restart|deallocate|scale|swap|import|purge|assign|deploy|apply|restore|failover|promote|clone|copy|reset|regenerate|rotate|move|resize|redeploy|reimage|convert|upgrade|set-[\w-]+)(?=\s|$)
match: \bgcloud\s+([\w-]+\s+)+(create|delete|update|deploy|start|stop|reset|resize|import|patch|apply|clone|failover|restore|promote-replica|move|enable|disable|attach-[\w-]+|detach-[\w-]+|set-[\w-]+|add-[\w-]+|remove-[\w-]+)(?=\s|$)
match: \bdoctl\s+([\w-]+\s+)+(create|delete|update|apply|tag|untag|rebuild|resize|power-on|power-off|power-cycle|reboot|shutdown|fork|restore|migrate|attach|detach|assign|unassign|reset|upgrade)(?=\s|$)
match: \bkubectl\s+(?!.*--dry-run=(server|client))(.*\s)?(apply|create|delete|patch|replace|scale|edit|label|annotate|taint|drain|cordon|uncordon|set|run|exec|cp|debug|rollout\s+(restart|undo))\b
match: \bhelm\s+(install|upgrade|uninstall|rollback|delete)\b
match: \bansible-playbook\b(?!.*--check)|\bansible\s.*-m\s+(shell|command|raw|service|systemd|package|apt|yum|dnf|copy|file|user)\b
match: \b(systemctl\s+(start|stop|restart|reload|enable|disable|mask)|reboot|shutdown|iptables\s+-[ADIRF]|ufw\s+(allow|deny|delete|enable|disable))\b
match: \b(qm|pct)\s+(start|stop|shutdown|reboot|destroy|rollback|snapshot|delsnapshot|migrate|set|resize|create|restore)\b|\bha-manager\s+(set|add|remove|migrate|relocate)\b
match: \bgovc\s+(vm\.(power|destroy|create|change|clone|migrate)|snapshot\.(create|remove|revert))\b|\bvirsh\s+(start|shutdown|reboot|destroy|undefine|setvcpus|setmem|snapshot-(create|delete|revert))\b
match: \brestic\s+(.*\s)?(forget|prune|restore|unlock)\b|\bborg\s+(.*\s)?(delete|prune|compact|extract)\b
match: \.(create|delete|update|put|modify|terminate|start|stop|reboot|restore|attach|detach|associate|disassociate|run|invoke|rotate|purge|import)_[a-z0-9_]+\(|\bbegin_(create|delete|update|start|stop|restart|deallocate)[a-z_]*\(
match: \bcurl\b.*--aws-sigv4|\b(az\s+rest|gcloud\s+.*--impersonate)\b.*--method\s+(put|post|patch|delete)\b
match: \bssh\b.*\bdocker(\s+compose|-compose)?\s+(.*\s)?(down|up|restart|stop|start|rm|rmi|kill|exec|run|pull|create|scale|update|prune|cp)\b|\bdocker\s+(-H|--host)[\s=]*ssh://\S+\s+(.*\s)?(compose\s+)?(down|up|restart|stop|start|rm|rmi|kill|exec|run|pull|create|scale|update|prune|cp)\b
- Before running it, did you show the user what you found, the fix, the risks and how to undo it, in plain words,
  and get a clear yes for these exact commands?
- Which environment and account/subscription/project did this run against? Did you check the workspace, backend and
  credentials first, or assume them?
- Did you read the whole plan? List every destroy and replace (`-/+`) and say why each is intended. A replace of a
  stateful resource (database, volume, bucket, key) is data loss.
- Was the apply run from the saved, reviewed plan file (`plan -out` then `apply <file>`), not a fresh auto-approve?
- After apply, does a new plan show no changes (`plan -detailed-exitcode` exits 0)? A diff means drift or a
  perpetual diff.
- Did you probe it from the consumer's side, as the workload identity (`dig`, `curl`, `nc`, the allowed call and one
  denied call)? Show the output.
- Any state edit, import or console change? Is it in code now, and did the user approve it?
- What is the rollback, and has it been tried?
- What does this change in the monthly bill? Is there a cheaper option with the same performance, and did you say so?
- Is your reply in plain words someone without infra experience can follow, with every risk stated plainly?

### gate: secrets
files: (^|/)\.secrets?(/|$)|\.secret$
files: (^|/)\.env(\.(?!example$|sample$|template$)[^/]+)?$
files: (^|/)\.aws/(credentials|sso/cache/|cli/cache/)|(^|/)\.azure/(msal_token_cache|accessTokens|service_principal_entries)
files: (^|/)\.config/gcloud/(credentials\.db|access_tokens\.db|legacy_credentials/|application_default_credentials\.json)
files: (^|/)\.config/doctl/config\.yaml$|(^|/)\.kube/config$|(^|/)\.ssh/id_[^/]*$|\.(pem|key|p12|pfx|jks|keystore)$
files: (^|/)(terraform\.tfstate(\.backup)?|[^/]*\.tfstate)$
match: \baws\s+secretsmanager\s+get-secret-value\b|\baws\s+ssm\s+get-parameters?(-by-path)?\b.*--with-decryption|\baws\s+(sso\s+get-role-credentials|configure\s+(get|export-credentials)|sts\s+get-session-token|ecr\s+get-login-password|iam\s+create-access-key)\b
match: \baz\s+(keyvault\s+secret\s+(show|download)|account\s+get-access-token|storage\s+account\s+(keys\s+list|show-connection-string)|ad\s+sp\s+credential\s+reset)\b|\baz\s+.*\blist-(keys|credentials|connection-strings)\b
match: \bgcloud\s+(secrets\s+versions\s+access|auth\s+(print-access-token|print-identity-token|application-default\s+print-access-token)|iam\s+service-accounts\s+keys\s+create)\b
match: \bdoctl\s+(auth\s+token|kubernetes\s+cluster\s+kubeconfig\s+show|databases\s+(connection|user\s+get))\b
match: \bkubectl\s+get\s+secrets?\b.*(-o|--output)[\s=]*(yaml|json|jsonpath|go-template)|\bkubectl\s+config\s+view\b.*--raw
match: \b(terraform|tofu)\s+((output|show)\s+[^|]*-json(?![^|]*\|)|output\s+[^|]*-raw|state\s+pull(?![^|]*\|))
match: (^|[;&|]\s*)(printenv|env|set|export\s+-p|declare\s+-x)\s*($|[;&|])

### gate: protect
files: (^|/)\.claude/settings(\.local)?\.json$|(^|/)\.claude/hooks/|(^|/)\.claude/goodbehavior/profiles/

### gate: investigation
claims: root cause|the cause (is|was)|caused by|the (issue|problem) (is|was)|it'?s because|that'?s why|explains (it|the)
- What exactly is the symptom, and where was it seen: environment, account, time window, network position?
- Which statements come from output you ran in this session, and which are inference? Label each, and quote the
  command for the observed ones.
- Did you check the live state, not just the code? Code, state and the real resource can disagree (drift, console
  edits, a failed apply).
- What changed when it started? Check the deploy history, the audit log, the last applies, cert expiry and quota.
- Does the cause explain every symptom, including the timing? Which alternatives did you rule out (DNS, firewall or
  security group, IAM, routing, TLS, quota, provider incident), and how?
- Were all probes read-only? If you changed anything to test, did you revert it and say so?
- What is still unknown, and which probe would settle it?
- Did you propose the fix (what it does, why it works, what could break, how to undo it) and ask, instead of
  applying it? Is it in plain words someone without infra experience can follow?
