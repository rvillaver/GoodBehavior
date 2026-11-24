---
name: devops/baseline
use-when: any devops project, whatever the provider; the provider guides next to this file map each rule to services and CLI probes
---

# DevOps baseline: cross-cloud rules, each with its live probe

Every rule here is paired with a **probe**: the check that shows the rule holds in the live environment. A rule with
no probe result is unverified, however good the code looks. Provider guides (`aws.md`, `azure.md`, …) give the
concrete service names and CLI commands for each rule.

How to run probes:
- **Read-only by default.** A probe reads state; it does not change it. A probe that changes anything (failover,
  restore, rotation, a deliberate denied write) is marked **(pause point)**: propose it and get the user's yes first,
  in every environment, per `devops.md`. Prefer non-prod; prod only as a planned, user-approved exercise.
- **From the consumer's position.** Run reachability and access probes as the workload identity and from the
  workload's network, not from your admin login on your laptop. An admin probe passes where the workload fails.
- **Name where it ran.** Every probe result records the environment and the account/subscription/project.

## IaC and state

- **rule:** All infrastructure is defined in code in version control. Nothing is created or changed by hand in the
  console, except break-glass, which is then written back into code.
  **probe:** run the plan against the live environment; it shows no changes (`terraform plan -detailed-exitcode`
  exits 0, or your tool's equivalent). A diff means drift or an unrecorded console change.
- **rule:** State is remote, encrypted, versioned and locked, never a local file or committed to git.
  **probe:** read the backend config, then list the state bucket/container and confirm versioning and encryption are
  on. Start two plans at once and confirm the second waits on, or fails on, the lock.
- **rule:** Each environment has its own state and its own credentials, so a dev apply cannot touch prod.
  **probe:** with dev credentials, run a read against a prod resource and confirm it is denied.
- **rule:** Modules and providers are pinned to exact versions.
  **probe:** grep the version constraints and the lock file; no unpinned or open-ended `>=` without an upper bound.

## CI/CD

- **rule:** Every change reaches an environment through the pipeline: plan on pull request, a reviewed apply on merge.
  **probe:** open a test PR and confirm the plan is posted to it. Check the deploy history: every prod apply maps to a
  merged commit.
- **rule:** The pipeline authenticates with short-lived federated credentials (OIDC), not long-lived keys stored as
  secrets.
  **probe:** list the CI secrets: no static cloud keys. Read the cloud's trust policy and confirm it is scoped to this
  repo and branch/environment.
- **rule:** Prod deploys need an approval gate and run only from the protected branch.
  **probe:** read the branch protection and environment rules. Confirm a run from a non-protected branch cannot reach
  prod credentials.
- **rule:** A deploy can be rolled back, and the rollback path has been used.
  **probe:** **(pause point)** in non-prod, deploy the previous version through the pipeline and confirm the health
  check passes.

## Code

Audit the code itself, not only what it built: Terraform, pipelines, scripts, charts and Dockerfiles. Run every
scanner on the whole repo (and the secret scanner on the whole git history), not only on the files you changed.
These are file reads, safe to run without asking. A tool that isn't installed is a "not checked" row, never a pass.
The scanners named below are defaults: where the project already runs its own for the same rule, use that.

- **rule:** No secret is in the repo or its history. Deleting a file does not remove it from history: a key that was
  ever committed must be revoked and replaced.
  **probe:** `gitleaks git . --redact --no-banner` (gitleaks 8.19 or later; older versions use `gitleaks detect`).
  `--redact` keeps the values out of the output. For each hit, say whether the file is still tracked
  (`git ls-files --error-unmatch <file>`), and treat a hit in a state file, kubeconfig or `.tfvars` as real until shown
  otherwise.
- **rule:** Infrastructure code has no known misconfigurations: open security groups, unencrypted storage, public
  buckets, privileged containers, missing logging.
  **probe:** `trivy config --severity HIGH,CRITICAL .` and `checkov -d . --compact --quiet` on the whole repo; every
  finding is fixed or has a written reason.
- **rule:** IaC code passes its linter: no unused variables or outputs, no deprecated syntax, version constraints
  set.
  **probe:** the IaC tool's linter prints no warnings. Terraform/OpenTofu: `tflint --recursive` (rule
  `terraform_unused_declarations` finds dead variables); other tools: their own linter (`ansible-lint`, `cfn-lint`,
  `bicep lint`, …).
- **rule:** Shell scripts pass a linter (ShellCheck).
  **probe:** `git ls-files '*.sh' | xargs shellcheck -S warning` prints nothing.
- **rule:** Pipelines are safe: third-party actions pinned to a full commit SHA, the token has only the permissions
  the job needs, and no untrusted input (PR titles, branch names, issue text) is pasted into a `run:` step.
  **probe:** GitHub: `zizmor .github/workflows` and `actionlint` print no findings. Any CI (Gitea, GitLab, GitHub):
  `grep -rnE 'uses: [^#]*@(v?[0-9]+(\.[0-9]+)*|main|master)\s*$' <workflow-dir>` lists actions not pinned to a SHA;
  `grep -rnE '\$\{\{ *(github|gitea)\.event\.(pull_request|issue|comment|head_commit)' <workflow-dir>` lists untrusted
  input to review.
- **rule:** No copy-paste. The same block repeated across environments, modules, workflows or scripts belongs in one
  module, `for_each`, shared workflow or function, so a fix lands everywhere at once.
  **probe:** `jscpd --min-lines 8 --format "bash,yaml" --ignore "**/.terraform/**,**/node_modules/**" .` (jscpd 4.0.5)
  reports the duplicated share (it doesn't parse `.tf` files). For Terraform, compare the environment roots:
  `diff -r <env-a-dir> <env-b-dir>`; differences should be only in variables and backend.
- **rule:** No dead code: commented-out resources, scripts nothing calls, workflows that never run, modules no root
  uses.
  **probe:** for each script and module, `git grep -n <name>` finds a caller; `grep -rnE '^\s*#\s*(resource|module) "' --include='*.tf' .`
  lists commented-out blocks.

## Secrets and identity

- **rule:** Every sensitive key (database passwords, API tokens, signing and encryption keys, webhook secrets, cloud
  keys) is stored in the platform's secret manager: AWS Secrets Manager or SSM Parameter Store `SecureString`, Azure
  Key Vault, GCP Secret Manager, DigitalOcean Secrets Manager, or a self-hosted one (OpenBao, Vault, Infisical, …)
  on-prem and in clusters; whichever the project already uses counts. Code,
  pipelines and workloads fetch it by reference at run time. A key anywhere else is a finding, "only dev" included:
  code or git history, `.tfvars`, Terraform state outputs, CI variables, app specs, plain environment variables, a
  Kubernetes Secret applied by hand, a file on a server, an image, a CI log. (Replaces the shorter "secrets live in a
  secret manager" rule.)
  **probe:** audit it every time, as a **key inventory**, names only, never values:
  1. Repo and history: `gitleaks git . --redact --no-banner`.
  2. Key-like names set to a literal in tracked files (prints file and line only, not the value):
     `git grep -nIiE '(password|passwd|secret|token|api_?key|private_?key|access_?key)[a-z0-9_]*"?[[:space:]]*[:=][[:space:]]*"?[a-z0-9/+]' -- ':!*.md' ':!*.example' ':!.claude' | cut -d: -f1,2`.
     Review each hit by line number; a reference (`var.x`, `${...}`) is fine, a literal is a finding.
  3. Where the platform hides keys at run time (function and container environment variables, app settings, app
     specs, cluster Secrets, `.env` files on servers): the provider guide's inventory probe.
  4. The secret manager's own list of names (provider guide).
  Write the inventory as a table: key name, where it was found, in the manager (yes/no), rotation or expiry, who can
  read it. Every key found in 1–3 that has no manager entry is a finding.
- **rule:** Access to the secret manager is least privilege and logged: each workload reads only its own secrets,
  humans don't read production values by default, and every secret has an owner and a rotation or expiry date.
  **probe:** read the secret manager's access policy (provider guide) and confirm no wildcard read for workloads or
  humans; find a recent secret read in the audit log, tied to a named identity.
- **rule:** Workloads use managed or workload identities, not embedded keys.
  **probe:** from inside the workload, ask the platform who it is (the provider's identity call) and confirm it is the
  expected role, not a user or a long-lived key.
- **rule:** Least privilege: each identity can do its job and nothing more.
  **probe:** **(pause point)** as the workload identity, try one action it must not do (read another app's secret,
  write outside its bucket) and confirm it is denied. Use a harmless target.
- **rule:** Humans use SSO with MFA. Root or owner accounts are locked away with no access keys.
  **probe:** list the root/owner credentials: no access keys, MFA on. List users with console passwords but no MFA:
  none.
- **rule:** Secrets rotate, and the workload survives rotation.
  **probe:** read the rotation config and last-rotated date. **(pause point)** in non-prod, rotate once and confirm the
  workload keeps working.

## Networking

- **rule:** Nothing is public unless it is meant to be. Databases, caches and admin ports are reachable only from
  their consumers.
  **probe:** from outside the network, `nc -zv <host> <port>` on the database and admin ports times out or is
  refused. From the app's subnet, the same call connects.
- **rule:** Ingress is limited to what is needed. No `0.0.0.0/0` on SSH, RDP or database ports.
  **probe:** list the firewall/security-group rules and grep for open-world sources on non-HTTP ports.
- **rule:** Public endpoints serve valid TLS, renewed automatically.
  **probe:** `openssl s_client -connect <host>:443 -servername <host>` shows a trusted chain and an expiry date more
  than 14 days away. Confirm the renewal job or managed certificate exists.
- **rule:** DNS records are in code and resolve as intended from each side (public and private).
  **probe:** `dig +short <name>` from outside and from inside the network; each returns the expected address.
- **rule:** Outbound traffic goes through a known path (NAT, proxy or egress firewall).
  **probe:** from the workload, call an external echo service (e.g. `curl -s https://ifconfig.me`) and confirm the
  source address is the expected NAT/egress IP.

## Zero trust

Zero trust is the default for every design, proposal and audit: no request is trusted because of where it comes
from. Inside the VPC, the cluster or the VPN counts for nothing. Every call proves who it is, gets only what that
identity needs, with short-lived credentials, and leaves a log entry. A design that depends on "it's on the internal
network" is a finding, written in the "Security findings" format.

- **rule:** Internal services require authentication too: service-to-service calls carry an identity (mTLS, signed
  tokens, the provider's IAM auth), not just a source address.
  **probe:** from another host or pod in the same network, call an internal service with no credentials:
  `curl -s -o /dev/null -w '%{http_code}\n' http://<internal-service>:<port>/<path>` returns `401` or `403`, not
  `200`.
- **rule:** Default deny between workloads: each one accepts traffic only from the callers it needs. Firewall rules
  name the calling group or identity, not a whole subnet or VPC range.
  **probe:** list the rules (provider guide; on Kubernetes `kubectl get networkpolicy -A`, with a default-deny policy
  in every application namespace). Look for rules whose source is the whole VPC range or `10.0.0.0/8`.
- **rule:** People reach admin tools (dashboards, Grafana, Argo, OpenBao UI, databases) through single sign-on with
  MFA at an identity-aware proxy or zero-trust access service, not through a flat VPN that opens the whole network.
  **probe:** from outside, without signing in:
  `curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://<admin-tool-host>/` returns `401`/`403`, or a
  redirect to the identity provider. A login page served by the tool itself, reachable by anyone, is a finding.
- **rule:** Credentials are short-lived: workload identity for services, OIDC federation for pipelines, temporary
  elevated access for people. Long-lived keys are the exception, listed, scoped and rotated.
  **probe:** list long-lived keys and their age (provider guide: access keys, service account keys, API tokens).
  Each one older than 90 days, or with no owner, is a finding.
- **rule:** Permissions are explicit: no wildcard actions or resources, no shared accounts, unused rights removed.
  **probe:** `grep -rnE '"Action"[[:space:]]*:[[:space:]]*"\*"|actions[[:space:]]*=[[:space:]]*\["\*"\]|"Resource"[[:space:]]*:[[:space:]]*"\*"' --include='*.tf' --include='*.json' --exclude-dir=.terraform .`
  lists wildcards in code; the provider's unused-access report (provider guide) lists rights nobody uses.
- **rule:** Traffic is encrypted inside the network too: TLS to databases, caches and internal APIs.
  **probe:** the database requires TLS: MySQL `SHOW VARIABLES LIKE 'require_secure_transport';` is `ON`; PostgreSQL
  `SELECT count(*) FROM pg_stat_ssl JOIN pg_stat_activity USING (pid) WHERE NOT ssl AND client_addr IS NOT NULL;`
  is `0` (connect over TLS to run it, or it counts its own connection).
- **rule:** Every access is logged under a named identity: no shared logins, and admin actions can be traced to a
  person.
  **probe:** pick one recent admin action (an apply, a secret read, a login to an admin tool) and find it in the
  audit log with a named user or workload identity.

## Observability

- **rule:** Logs from every workload and the control plane (audit log) are kept centrally, with a set retention.
  **probe:** trigger a known event (a request, a denied action) and find it in the central log within minutes. Read
  the retention setting.
- **rule:** Key signals have alerts that reach a human: availability, error rate, saturation, cost spikes.
  **probe:** **(pause point)** fire a test alert (or breach a threshold in non-prod) and confirm it reaches the
  on-call channel.
- **rule:** Each public service has a health check or uptime probe from outside.
  **probe:** read the uptime check's last results. **(pause point)** Take a non-prod instance down and confirm the check fails.
- **rule:** The cloud audit log is on in every account/region and stored where workloads cannot delete it.
  **probe:** confirm the audit trail is enabled and logging, then try to delete it as a workload identity: denied.

## Security and attack surface

Assume every public endpoint is being scanned and attacked right now by automated tools. Each probe below shows
whether a defense is really on. Write findings in the "Security findings" format from `devops.md` (risk, how
likely, impact, fix, evidence), in plain words. Probes that send attack-like traffic are marked **(pause point)**:
they can trip alerts or get your own address blocked, so ask first and run them against non-prod where you can.

- **rule:** Know the whole attack surface: every public IP, DNS name, load balancer, bucket and open port is listed
  and owned.
  **probe:** list public addresses and DNS records from the provider (see the provider guide), then from outside
  scan only your own addresses: **(pause point)** `nmap -Pn --top-ports 100 <your-public-ip>`. Every open port has
  a reason.
- **rule:** No dangling DNS: no record points at a resource that no longer exists (an attacker can claim it and
  serve content on your name).
  **probe:** `dig +short CNAME <name>` for each record; the target still exists and is yours.
- **rule:** Public web apps and APIs sit behind a WAF or CDN with managed rule sets on: SQL injection, cross-site
  scripting, known bad inputs, plus rate-based rules.
  **probe:** read the WAF config (provider guide). **(pause point)** from outside, send one harmless test pattern and
  expect a block: `curl -s -o /dev/null -w '%{http_code}\n' "https://<host>/?id=1%27%20OR%20%271%27=%271"` returns
  `403`.
- **rule:** The origin can't be reached around the WAF: servers and load balancers accept traffic only from the CDN
  or WAF.
  **probe:** connect straight to the origin address: `curl -sk -o /dev/null -w '%{http_code}\n' --connect-timeout 5 --resolve <host>:443:<origin-ip> https://<host>/`
  fails or times out.
- **rule:** DDoS and abuse limits are on: the provider's network-level protection, and rate limits on login, signup,
  password reset, search and costly API calls.
  **probe:** read the rate-limit rules (provider guide, or the CDN). **(pause point)** in non-prod, send a burst:
  `for i in $(seq 1 60); do curl -s -o /dev/null -w '%{http_code}\n' https://<host>/login; done | sort | uniq -c`
  shows `429` (or the WAF's block code) once the limit is passed.
- **rule:** Bot protection on login, signup, checkout and contact forms (bot management, CAPTCHA or a challenge), so
  credential stuffing and fake sign-ups are stopped.
  **probe:** read the bot rules on those paths in the WAF or CDN config, and check the WAF log for blocked bot
  traffic.
- **rule:** Injection can't reach the data: the WAF blocks known patterns, the app uses parameterized queries, and
  the app's database user has only the rights it needs (no owner, superuser or schema-change rights).
  **probe:** list the app user's grants (`\du` and `\dp` in `psql`, `SHOW GRANTS FOR '<user>'@'%';` in MySQL, the
  user's role memberships in SQL Server); no admin or DDL rights.
- **rule:** TLS 1.2 or higher only, with HSTS and basic security headers.
  **probe:** `openssl s_client -connect <host>:443 -servername <host> -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null`
  fails with a handshake or protocol-version alert. (Without `-cipher 'DEFAULT@SECLEVEL=0'`, OpenSSL 3+ refuses
  TLS 1.1 on its own side, so the probe "fails" even when the server would accept it.)
  `curl -sI https://<host> | grep -iE 'strict-transport-security|content-security-policy|x-content-type-options|x-frame-options'`
  shows each header.
- **rule:** Admin access never faces the internet: no public SSH, RDP or database ports; use the provider's session
  manager, a bastion, a VPN or zero-trust access, with MFA.
  **probe:** from outside, `nc -zv -w 3 <host> 22` and `nc -zv -w 3 <host> 3389` fail.
- **rule:** Known vulnerabilities are found and fixed: infrastructure code, container images and servers are scanned,
  and HIGH or CRITICAL findings have an owner and a date.
  **probe:** `trivy config --severity HIGH,CRITICAL --exit-code 1 <iac-dir>` and `checkov -d <iac-dir> --compact --quiet`
  pass; `trivy image --severity HIGH,CRITICAL <image>` for each image in use; the provider's vulnerability findings
  (provider guide).
- **rule:** Threat detection is on and someone reads it: the provider's detection service, WAF logs, and alerts on
  spikes of blocked requests, 4xx/5xx and failed logins.
  **probe:** the detection service is enabled with no unreviewed high or critical findings (provider guide); a
  recent WAF log entry can be found.

## Backup and DR

- **rule:** Every stateful store (databases, volumes, buckets, state files) has automated backups with a known
  retention.
  **probe:** list the backup jobs/snapshots for each store and confirm the latest is inside the expected window.
- **rule:** Backups are restore-tested. A backup that was never restored does not count.
  **probe:** **(pause point)** restore the latest backup into a scratch target, never over the source. Run a data
  check (row counts, a known record, the app's health check against it) and keep the restore log with timings.
- **rule:** RPO and RTO are written down, and the restore test meets them.
  **probe:** compare the backup age (RPO) and the restore duration from the log (RTO) to the written targets.
- **rule:** Backups are protected from the account that made them: a separate account/vault, immutability or
  object lock.
  **probe:** as the workload or deploy identity, try to delete a backup: denied. Read the lock or immutability setting.
- **rule:** Failover across zones or regions works, where the design claims it.
  **probe:** **(pause point)** in non-prod, or as a scheduled prod exercise, fail over and measure recovery against
  the RTO.

## Performance

Performance and cost are one question: the cheapest setup that meets the target. Measure from the consumer's side
(the user's region, the calling service), not from inside the server. A number without its window, percentile and
place of measurement is not evidence.

- **rule:** Each public service has a written target: p95 (and p99 where it matters) latency, error rate, and the
  peak load it must carry. Without a target, "fast enough" and "oversized" can't be judged.
  **probe:** find the target in the repo or docs; compare it with 14+ days of measured p95 latency and error rate
  from the load balancer or ingress (provider guide). No written target is a finding.
- **rule:** You know where the time goes on the request path: DNS, connect, TLS, time to first byte, transfer.
  **probe:** from the users' region, 20 timed requests:
  `for i in $(seq 1 20); do curl -s -o /dev/null -w '%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}\n' https://<host>/<path>; done | sort -k5 -n | awk '{a[NR]=$0} END {print "median:", a[int(NR/2)]; print "p95:   ", a[int(NR*0.95)]}'`.
  Columns are cumulative seconds: DNS, TCP connected, TLS done, first byte, total. A big jump at first byte is the
  server or what it calls; at connect or TLS it is distance or the network.
- **rule:** Capacity is measured, not guessed: a load test in non-prod finds where latency or errors break the
  target, which resource saturates first, and the headroom over the expected peak (aim for 2×).
  **probe:** **(the user runs it, never Claude)** a stepped load test with the team's load tool (for example k6, with the script under "Load
  test" below. Never run a load test during an audit or as a check: real load can take down a shared or production
  environment. Suggest it instead: hand the user the script, the command, which environment to point it at
  (non-prod), and what to watch (CPU, memory, database connections, queue depth). Running it is their call. If they
  run it, record the step where the thresholds failed and what saturated. Until then, the row is **not checked**
  ("load test suggested, not run").
- **rule:** Autoscaling keeps up: it triggers before saturation, its maximum is above the load-test peak, and the
  time from trigger to new capacity serving traffic is known (new nodes take minutes, new pods seconds).
  **probe:** read each autoscaler's target, minimum and maximum (provider guide). Anything sitting at its maximum is
  a finding. From the load test, time from the threshold crossing to the new instance passing its health check.
- **rule:** Cacheable content is cached: static files and cacheable API responses come from a CDN or cache, with
  `Cache-Control` set, and the hit ratio is known.
  **probe:** request the same static file twice:
  `curl -sI https://<host>/<static-file> | grep -iE '^(cache-control|age|x-cache|cf-cache-status):'`. The second
  response shows a cache hit (`HIT`, or an `age` above 0). Read the CDN's hit ratio (provider guide); under 80% on
  static content means wrong headers or cache keys.
- **rule:** Text responses are compressed and served over HTTP/2 or later.
  **probe:** `curl -s -o /dev/null -H 'Accept-Encoding: br, gzip' -D - https://<host>/ | grep -i '^content-encoding'`
  shows `br` or `gzip`; `curl -s -o /dev/null -w '%{http_version}\n' https://<host>/` prints `2` or `3`.
- **rule:** Things that talk to each other sit close together: app, database, cache and image registry in the same
  region, and in the same zone where the provider charges or adds latency across zones. No cross-region call on
  the request path unless the design needs it.
  **probe:** list the region (and zone) of each service, database, cache and registry (provider guide). From the
  workload, time a TCP connect to its database:
  `curl -s -o /dev/null --max-time 2 -w '%{time_connect}\n' telnet://<db-host>:<port> </dev/null` stays under a few
  milliseconds in-region. curl then waits for the timeout and exits 28; the printed time is the result. `0.000000`
  means it never connected.
- **rule:** The database is not the hidden bottleneck: slow queries are logged and the top ones reviewed, hot
  queries have indexes, and the app uses a connection pool with connections well under the server's maximum.
  **probe:** top queries by total time: PostgreSQL
  `SELECT round(total_exec_time) AS ms, calls, left(query, 80) FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10;`
  (needs the `pg_stat_statements` extension); MySQL
  `SELECT ROUND(SUM_TIMER_WAIT/1e12) AS s, COUNT_STAR, LEFT(DIGEST_TEXT, 80) FROM performance_schema.events_statements_summary_by_digest ORDER BY SUM_TIMER_WAIT DESC LIMIT 10;`.
  Connections: PostgreSQL `SELECT count(*) FROM pg_stat_activity;` against `SHOW max_connections;`, MySQL
  `SHOW GLOBAL STATUS LIKE 'Max_used_connections';` against `SHOW VARIABLES LIKE 'max_connections';`. Peak above
  80% of the maximum is a finding. Run as a read-only database user the user provides; never read its password.
- **rule:** Startup is fast where it matters: small images, no cold start on the latency-critical path (minimum
  instances or warm capacity there), and readiness probes that pass as soon as the app can serve.
  **probe:** image sizes (`docker image ls`, or the registry); time from pod scheduled to ready
  (`kubectl get events -A --field-selector reason=Pulled` shows pull times); for serverless, the provider's
  cold-start or init-duration metric (provider guide).
- **rule:** Saturation is alerted before users feel it: CPU throttling, memory pressure, disk I/O queue, connection
  pool waits and queue depth, not only CPU percent.
  **probe:** list the alert rules and match each saturation signal above to one. On Kubernetes with Prometheus, CPU
  throttling per container:
  `sum by (namespace, pod, container) (rate(container_cpu_cfs_throttled_periods_total[5m])) / sum by (namespace, pod, container) (rate(container_cpu_cfs_periods_total[5m])) > 0.25`.
- **rule:** Every sizing or performance change is measured before and after: the same metrics (p95 latency, error
  rate, saturation of the resized resource), over the same length of window, under comparable load. A change that
  saves money but breaks the target is rolled back.
  **probe:** a before/after table in the change record: metric, before, after, window, source. For a change you
  can't wait on prod traffic for, suggest the load test above in non-prod, before and after; the user decides
  whether to run it.

**Load test (suggest it; the user runs it).** A sample stepped k6 script (k6 2.x); if the team already uses another
load tool (JMeter, Gatling, Locust, …), write the same steps and thresholds in that instead. It raises the request rate in steps and
fails when p95 goes over 500 ms or more than 1% of requests fail (k6 then exits 99). Set the steps and thresholds
from the written target. Claude writes and hands over this script but never runs it: load sent at the wrong host can
break a production environment, so whether, when and where to run it is the user's decision.

```js
// load.js: run with  k6 run -e TARGET=https://<non-prod-host>/<path> load.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    steps: {
      executor: 'ramping-arrival-rate',
      startRate: 5, timeUnit: '1s', preAllocatedVUs: 50, maxVUs: 500,
      stages: [
        { target: 20, duration: '2m' }, { target: 20, duration: '3m' },
        { target: 50, duration: '2m' }, { target: 50, duration: '3m' },
        { target: 100, duration: '2m' }, { target: 100, duration: '3m' },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const res = http.get(__ENV.TARGET);
  check(res, { 'status is 2xx': (r) => r.status >= 200 && r.status < 300 });
}
```

## Cost

- **rule:** Every resource carries owner, environment and cost-center tags, enforced by policy.
  **probe:** query the provider for resources missing the required tags; the list is empty. Try creating an untagged
  resource in non-prod (**pause point**); the policy blocks it.
- **rule:** Budgets with alerts exist per account/project and environment.
  **probe:** list the budgets and their alert recipients, and confirm the thresholds fire before the money is spent.
- **rule:** No idle spend: unattached disks, idle IPs, stopped-but-billed instances, old snapshots outside retention.
  **probe:** list unattached volumes, unassociated IPs and snapshots older than retention; each has an owner or goes.
- **rule:** Non-prod is sized down and scheduled off when unused.
  **probe:** read the schedules and instance sizes for non-prod; compare against prod.
- **rule:** Not over-provisioned: sizes match real use. Low average and p95 use over 14+ days (for example CPU under
  20% and memory under 40%) means a smaller size, a burstable type or autoscaling.
  **probe:** pull 14–30 days of CPU, memory, disk and network use (average and p95) for each instance, database and
  node pool, and compare with its size. Memory often needs the provider's agent; say if it's missing.
- **rule:** Not under-provisioned: running hot costs money too (slow responses, crashes, retries, extra replicas
  added to compensate). Sometimes one bigger size is cheaper than several small ones.
  **probe:** look for p95 CPU over 80%, out-of-memory kills, exhausted burst credits, throttled disk or API calls,
  long queues, and autoscaling stuck at its maximum.
- **rule:** Redundancy matches the written availability target. Prod keeps what the target needs. Dev and test don't
  run multi-zone databases, a NAT gateway per zone or spare replicas unless there's a reason. No two resources doing
  the same job (unused load balancers, duplicate log pipelines, forgotten replicas).
  **probe:** list multi-zone, replicated and duplicated resources per environment and match each to the availability
  target. Anything that backs the target stays unless the user decides otherwise.
- **rule:** The pricing model fits the usage: commitments (reserved capacity, savings plans, committed use) for
  steady 24/7 load; spot or preemptible for work that can be interrupted; serverless or autoscaling for spiky load.
  Newer instance generations and ARM types often give the same performance for less. Commit only after removing
  idle resources and rightsizing, and only to the steady floor (the lowest hourly use over 30+ days), not the
  average (see "Order of the work" in `devops.md`).
  **probe:** read the commitment coverage and utilization reports (utilization under about 95% means the commitment
  is too big), and list instance families and generations in use against what is current.
- **rule:** Storage sits in the right tier: lifecycle rules move or expire old objects, logs have a retention, disk
  types match the IOPS really used.
  **probe:** list buckets without lifecycle rules, log groups without retention, and disks with provisioned IOPS far
  above measured use.
- **rule:** Data transfer is known and kept low: cross-zone, cross-region and NAT traffic are billed. Use private or
  gateway endpoints for the provider's storage and APIs; keep chatty services in the same zone.
  **probe:** break the bill down by usage type and check NAT bytes processed and inter-zone/region transfer.
- **rule:** Observability doesn't cost more than it's worth: log volume, metric series and trace sampling are known
  and capped. Debug logging is off in prod, noisy sources are filtered at the collector, and high-cardinality labels
  (user IDs, request IDs, full URLs) stay out of metrics.
  **probe:** top log sources by volume (provider guide); on Prometheus, the biggest metrics by series:
  `topk(10, count by (__name__)({__name__=~".+"}))` and the total `prometheus_tsdb_head_series`. A metric with
  tens of thousands of series usually has a per-user or per-request label.
- **rule:** Container registries clean up after themselves: untagged and old images expire by policy.
  **probe:** the registry's cleanup or lifecycle policy (provider guide) exists and keeps only what rollback needs.
- **rule:** Licenses are counted: Windows and SQL Server licenses bought with the VM, bring-your-own where you
  already own them, and the core count matches what is licensed.
  **probe:** list VMs by platform and size (provider guide) and compare with the license entitlements.
- **rule:** Every infrastructure change shows its cost before it is applied: the monthly delta is in the plan review,
  next to the plan.
  **probe:** the pipeline or the proposal shows a cost delta for the last few changes. A tool can do it from the
  plan, for example Infracost (`infracost diff --path <iac-dir>`), which sends resource types and sizes (not
  secrets) to its pricing API; ask the user before installing or using it, as with any scanner.
- **rule:** Unexpected spend is caught in days, not at month end: cost anomaly alerts are on, and cost is tracked
  per unit that matters (per environment, per customer or tenant, per thousand requests).
  **probe:** the provider's anomaly detection is enabled with a recipient (provider guide). Pick one unit and
  compute it for the last two months from the bill and the usage; a rise with no rise in usage is a finding.
