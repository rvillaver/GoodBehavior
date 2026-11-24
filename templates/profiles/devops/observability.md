---
name: devops/observability
use-when: the project runs or configures its own monitoring stack (Prometheus, Alertmanager, Loki, Grafana, or compatible ones such as Mimir, Thanos, VictoriaMetrics, Alloy); install next to the baseline
---

# Observability: rules for metrics, alerts, logs and dashboards, each with its probe

The baseline says what must be watched (Observability, Performance, Cost). This guide checks that the watching itself
works: alerts reach a person, logs arrive and stay out of trouble, and nobody outside can read or change any of it.

Probes marked "tested" were run in October 2026 against a throwaway local stack: Prometheus 3.5 (with its `promtool`),
Alertmanager 0.28 (`amtool`), Loki 3.5 (`logcli` 3.5) and Grafana 12.0, all in containers. Run the CLIs from their
images if they aren't installed, so nothing is installed on the machine:
`docker run --rm -v "$PWD":/w -w /w --entrypoint promtool prom/prometheus:v3.5.0 check rules rules/*.yml`
(`--entrypoint amtool prom/alertmanager:v0.28.1`, and `grafana/logcli:3.5.0` for logcli).

The probes use four addresses: `$PROM`, `$AM`, `$LOKI` and `$GRAFANA`. In a cluster, reach them with
`kubectl port-forward` (see `kubernetes.md`). Grafana probes need a token: ask the user for a **Viewer** service
account token in `$GRAFANA_TOKEN` (the admin-only probes say so). Never print it, and never use the admin password.
With the guard installed, put the Grafana address in the project's `.env` (`GRAFANA_URL=https://<grafana-host>`):
reads with the token then run, and writes still ask.

Reads of these APIs are safe. These change things and are a **(pause point)**: firing a test alert, adding or
expiring a silence, reloading a config (`/-/reload`), deleting series or logs, and any write to Grafana's API.

## Code

- **rule:** Alert rules, recording rules, the Alertmanager config, Loki config and Grafana dashboards and data sources
  live in Git and are deployed from there. A dashboard clicked together in the UI is lost with the database and
  can't be reviewed.
  **probe:** dashboards not loaded from files (tested: it listed the one made in the UI, not the provisioned one):
  `curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" "$GRAFANA/api/search?type=dash-db&limit=5000" | jq -r '.[].uid' | while read -r uid; do curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" "$GRAFANA/api/dashboards/uid/$uid" | jq -r 'select(.meta.provisioned != true) | "\(.dashboard.uid)  \(.dashboard.title)"'; done`
  prints nothing, or each one has an owner and a date to move it into Git.
- **rule:** Every config is checked in CI before it ships, so a typo can't break scraping or alerting.
  **probe:** these pass (tested): `promtool check config prometheus.yml`, `promtool check rules rules/*.yml`,
  `amtool check-config alertmanager.yml`, `loki -config.file=loki.yml -verify-config` (prints `config is valid`).
  The pipeline runs them on every change.
- **rule:** Alert rules have unit tests: given this input, this alert fires with these labels, and doesn't fire on
  normal data.
  **probe:** `promtool test rules tests/*.yml` prints `SUCCESS` (tested), and no alert is left without a test
  (tested: it listed the two untested ones):
  `comm -23 <(grep -ho 'alert: *[A-Za-z0-9_]*' rules/*.yml | sed 's/.*: *//' | sort -u) <(grep -ho 'alertname: *[A-Za-z0-9_]*' tests/*.yml | sed 's/.*: *//' | sort -u)`
  prints nothing, or only `Watchdog`.
- **rule:** Routing is tested too: a critical alert goes to the pager, a warning goes to a channel, nothing falls
  through to a default receiver that nobody reads.
  **probe:** `amtool config routes test --config.file=alertmanager.yml severity=critical alertname=<name>` prints the
  expected receiver (tested), one check per severity and team; `amtool config routes --config.file=alertmanager.yml`
  shows the tree.
- **rule:** No secrets in these files: receiver keys, webhook URLs, data source passwords and remote-write
  credentials come from files or the secret manager (`*_file` settings, `$__file{}` in Grafana, environment
  variables), not from the YAML in Git.
  **probe:** `grep -rniE '(api_key|password|token|routing_key|webhook_url|secret)\s*:\s*[^ ${]' <monitoring-dir>`
  finds only `*_file` settings and references; `gitleaks detect` finds nothing.

## Alerting

- **rule:** Alerts reach a person, end to end: rule → Alertmanager → the real pager or channel.
  **probe:** Prometheus sees its Alertmanagers: `curl -s $PROM/api/v1/alertmanagers | jq '.data.activeAlertmanagers'`
  is not empty (tested). **(pause point)** fire a test alert and confirm it arrives where on-call looks:
  `amtool --alertmanager.url=$AM alert add GoodBehaviorTest severity=warning --annotation='summary="test, please ignore"'`
  (tested: it reached the receiver in about 15 seconds). Quote annotation values, or amtool warns and falls back to
  its old parser.
- **rule:** The alert path is watched from outside: an always-firing alert (`Watchdog`, `expr: vector(1)`) goes to
  a heartbeat service (Healthchecks.io, a PagerDuty, Opsgenie or Grafana OnCall heartbeat) that pages when the
  heartbeat stops. Otherwise a dead Prometheus or Alertmanager looks exactly like a quiet night.
  **probe:** `amtool --alertmanager.url=$AM alert query alertname=Watchdog` shows it active (tested), and the
  heartbeat service shows a recent ping. **(pause point)** stop Prometheus in non-prod and confirm the page.
- **rule:** Every alert a person gets has a severity, a summary that says what is broken, a runbook link, and a
  `for:` long enough to skip blips.
  **probe:** alerting rules missing a runbook or a `for:` (tested: it caught both on a sample rule):
  `curl -s "$PROM/api/v1/rules?type=alert" | jq -r '.data.groups[].rules[] | select(.labels.severity != "none") | select(.annotations.runbook_url == null or .duration == 0) | .name'`
  prints nothing.
- **rule:** Page on symptoms users feel (error rate, latency, SLO burn rate) not on causes (one pod restarted, CPU
  at 80%). Each user-facing SLO has a fast-burn alert (for example 14.4× burn over 1h and 5m) and a slow-burn one
  (6× over 6h and 30m).
  **probe:** read the rules with `severity: critical`: each one maps to a user-facing symptom or SLO; `promtool test
  rules` covers both burn windows.
- **rule:** Alerts are not noise. An alert that fires for days and nobody fixes trains people to ignore the pager.
  **probe:** the longest-firing alerts over the last week:
  `topk(10, sum by (alertname) (count_over_time(ALERTS{alertstate="firing"}[7d])))` (tested; the number is
  evaluations spent firing, so compare alerts with each other). Apart from `Watchdog`, each one at the top is fixed,
  tuned or deleted.
- **rule:** Silences are short, owned and explained, so an alert isn't muted forever by accident.
  **probe:** silences that run past a week or have no named author (tested):
  `amtool --alertmanager.url=$AM silence query -o json | jq -r '.[] | select(.endsAt > (now + 7*86400 | todate) or .createdBy == "nobody") | [.id, .createdBy, .endsAt, .comment] | @tsv'`
  prints nothing. When adding one (a **(pause point)**), pass `--author` and a ticket in `--comment`.
- **rule:** Notifications don't fail silently: Alertmanager can reach every receiver, and its config reloaded.
  **probe:** `sum by (integration) (increase(alertmanager_notifications_failed_total[24h])) > 0` returns nothing and
  `alertmanager_config_last_reload_successful` is `1` (tested).

## Metrics

- **rule:** Every scrape target is up, and a missing target alerts. A target that disappears from discovery
  doesn't show as down: alert on `absent()` for the jobs that matter.
  **probe:** `up == 0` returns nothing (tested); `curl -s $PROM/api/v1/targets | jq -r '.data.activeTargets[] | select(.health != "up") | [.labels.job, .lastError] | @tsv'`
  lists no targets (tested: it showed the dead one with its DNS error); there is an `up == 0` or `absent(up{job="<job>"})`
  rule for each critical job (tested: `absent()` fires for a job with no targets).
- **rule:** Prometheus itself is healthy: config loaded, rules evaluate, alerts are sent, and rule groups finish
  inside their interval.
  **probe:** each returns nothing above zero (tested): `prometheus_config_last_reload_successful == 0`,
  `increase(prometheus_rule_evaluation_failures_total[1h]) > 0`,
  `increase(prometheus_notifications_dropped_total[1h]) > 0`,
  `prometheus_rule_group_last_duration_seconds > prometheus_rule_group_interval_seconds`.
- **rule:** Retention is set on purpose, by time and by size, so the disk never fills and history is as long as the
  team needs. Longer history goes to remote storage (Thanos, Mimir, a managed service), not a bigger disk.
  **probe:** `curl -s $PROM/api/v1/status/flags | jq '.data | {time: ."storage.tsdb.retention.time", size: ."storage.tsdb.retention.size"}'`
  shows both (tested); free disk on the data volume is above the size limit plus head room.
- **rule:** Metrics stay available when one Prometheus dies: two replicas scraping the same targets, or remote write
  to durable storage. Alertmanager runs as a cluster of three when it pages people.
  **probe:** `count by (job) (up{job=~"prometheus|alertmanager"})` shows the expected replicas (tested);
  `alertmanager_cluster_members` equals the cluster size on each member (tested on a single member: `1`).

## Logs

- **rule:** Logs from every workload arrive in Loki within a minute, and you can find one request by its ID.
  **probe:** trigger a known request and find it (tested):
  `logcli --addr=$LOKI query '{namespace="<ns>", app="<app>"} |= "<request-id>"' --since=10m --limit=5`.
- **rule:** Logs don't hold secrets or personal data. The collector (Alloy, Promtail, the OpenTelemetry Collector,
  Fluent Bit) drops or masks them before they leave the node; apps don't log them at all.
  **probe:** count, don't print, lines that look like secrets (tested: it counted one planted `password=` line and
  printed no log text):
  `logcli --addr=$LOKI instant-query 'sum by (app) (count_over_time({env="prod"} |~ "(?i)(password|passwd|secret|token|api[_-]?key)\\s*[=:]" [24h]))'`
  returns nothing. Never print the matching lines.
- **rule:** Labels are few and low-cardinality (app, namespace, env, level). User IDs, request IDs, IPs and URLs go
  in the log line or structured metadata, never in labels: every label value makes a new stream, and Loki slows
  down and costs more.
  **probe:** `logcli --addr=$LOKI series '{env="prod"}' --analyze-labels --since=1h` lists each label with its unique
  values (tested: it showed a planted `user_id` label); any label with values in the hundreds is a finding.
- **rule:** Loki keeps logs for a set time and deletes them after: retention is on in the compactor, and the bucket's
  own lifecycle rule matches it.
  **probe:** `curl -s $LOKI/config | grep -E '^\s*(retention_enabled|retention_period):'` shows
  `retention_enabled: true` and the agreed period (tested; ignore a second `retention_period: 0s` from the unused
  table manager). Read the bucket's lifecycle rule (provider guide).
- **rule:** Logs aren't dropped silently: discarded lines (rate limits, too many labels, too-old lines) alert.
  **probe:** `sum by (tenant, reason) (increase(loki_discarded_samples_total[24h])) > 0` returns nothing. A counter
  that first appeared inside the window shows 0 here (tested), so also read Loki's own
  `curl -s $LOKI/metrics | grep '^loki_discarded_samples_total'`.

## Security

- **rule:** Prometheus, Alertmanager and Loki have no login by default: anyone who reaches them can read every metric
  and log line, silence alerts, and (Loki) push or delete logs. They are never reachable from the internet, and
  inside the network only through an authenticating proxy or gateway (zero trust: being on the internal network is
  not a reason to trust a caller).
  **probe:** from outside, each public name or IP refuses or asks for a login:
  `curl -s -o /dev/null -w '%{http_code}\n' -m 5 https://<host>/api/v1/status/config` (and `/api/v2/silences`,
  `/loki/api/v1/labels`) prints `401`, `403` or times out, never `200`. Same for exporters:
  `curl -s -m 5 http://<public-ip>:9100/metrics | head -1` prints nothing.
- **rule:** Loki runs with `auth_enabled: true` when more than one team or tenant writes to it, and the gateway sets
  the tenant from the caller's identity, not from a header the caller chooses. With auth on, Loki only checks that
  an `X-Scope-OrgID` header is present: anyone who reaches Loki directly can name any tenant.
  **probe:** straight to Loki, `curl -s -o /dev/null -w '%{http_code}\n' $LOKI/loki/api/v1/labels` prints `401` when
  auth is on and `200` when it is off (tested both; `/config` doesn't show the setting). Through the gateway, a
  request with no credentials and a made-up `X-Scope-OrgID` header returns `401`.
- **rule:** Dangerous admin endpoints are off: Prometheus `--web.enable-admin-api` (deletes data) and
  `--web.enable-lifecycle` (reload and shut down over HTTP) stay off unless something needs them and they sit behind
  auth.
  **probe:** `curl -s $PROM/api/v1/status/flags | jq '.data | {admin: ."web.enable-admin-api", lifecycle: ."web.enable-lifecycle"}'`
  shows `"false"` for both (tested).
- **rule:** People sign in to Grafana with single sign-on and MFA; anonymous access is off; the built-in `admin`
  account has a strong, stored password or is disabled.
  **probe:** the login page shows the SSO settings without a login (tested):
  `curl -s $GRAFANA/login | grep -oE '"(oauth|disableLoginForm|anonymousEnabled)":(\{[^}]*\}|[a-z]+)'` shows an
  `oauth` provider, `anonymousEnabled:false`, and ideally `disableLoginForm:true`.
  `curl -s -o /dev/null -w '%{http_code}\n' $GRAFANA/api/search` prints `401` (tested). The default password fails:
  `curl -s -o /dev/null -w '%{http_code}\n' -u admin:admin $GRAFANA/api/user` prints `401` (tested: a fresh
  install prints `200`). The guard asks before this one, because it sends a password.
- **rule:** Grafana service accounts get the smallest role that works, and their tokens expire. A never-expiring
  Admin token in a CI variable is a full takeover of Grafana and every data source it can query.
  **probe:** needs an admin token, so ask the user to run it, or to give a short-lived one (tested: it found the
  token made with no expiry):
  `curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" "$GRAFANA/api/serviceaccounts/search?perpage=1000" | jq -r '.serviceAccounts[] | [.id, .name, .role] | @tsv' | while IFS=$'\t' read -r id name role; do curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" "$GRAFANA/api/serviceaccounts/$id/tokens" | jq -r --arg n "$name" --arg r "$role" '.[] | select(.expiration == null) | "\($n) (\($r)): token \(.name) never expires"'; done`
  prints nothing, and no service account has `Admin` without a written reason.
- **rule:** Grafana is patched: it has regular security releases, and it is often internet-facing.
  **probe:** `curl -s $GRAFANA/api/health | jq -r .version` (tested) is on a supported line with the latest
  security patch (check grafana.com/security/security-advisories).

## Performance

- **rule:** Dashboards and alerts that run a heavy query often use a recording rule instead, so Prometheus doesn't
  redo the same work on every refresh.
  **probe:** the slow part of queries: `max by (slice) (prometheus_engine_query_duration_seconds{quantile="0.9"})`
  (tested); `inner_eval` above a second points at a query to move into a recording rule. Dashboard refresh is not
  faster than the scrape interval.
- **rule:** Scrapes finish well inside their timeout, so no target goes missing under load.
  **probe:** `scrape_duration_seconds > 5` returns nothing (tested; default timeout 10s); a slow exporter gets a
  longer interval or is fixed.
- **rule:** Log queries start from labels, not a full scan: `{app="x"} |= "error"`, not `{env=~".+"} |~ "..."` over
  a week.
  **probe:** p99 of Loki read requests:
  `histogram_quantile(0.99, sum by (le, route) (rate(loki_request_duration_seconds_bucket{route=~".*query.*"}[5m])))`
  stays under a few seconds (tested: `NaN` means no queries in the window); slow routes trace back to dashboards
  that need narrower selectors.

## Cost

- **rule:** Every scrape job has limits, so one bad deploy that adds a per-user label can't blow up memory and the
  bill (baseline: observability spend).
  **probe:** the count of `sample_limit` settings matches the count of jobs (tested: `0` limits for `5` jobs):
  `curl -s $PROM/api/v1/status/config | jq -r .data.yaml | grep -cE '^\s+sample_limit:'` and
  `curl -s $PROM/api/v1/status/config | jq -r .data.yaml | grep -cE '^- job_name:'`. The baseline's
  top-10-metrics-by-series query shows nothing unexpected.
- **rule:** Metrics nobody uses are dropped at scrape time (`metric_relabel_configs` with `action: drop`), not
  stored and paid for.
  **probe:** take the top metrics by series (baseline) and search the dashboards and rules for each name:
  `grep -rl '<metric_name>' <dashboards-dir> rules/`. One used nowhere is a drop candidate.
- **rule:** Log volume is known per app, and debug logs stay off in prod.
  **probe:** biggest log sources by bytes:
  `logcli --addr=$LOKI instant-query 'topk(10, sum by (app) (bytes_over_time({env="prod"}[24h])))'` (tested); the
  top sources match what the team expects.

## Backup and DR

- **rule:** Losing the monitoring stack loses no config: everything comes back from Git. Long-term metrics and logs
  live in object storage with versioning; Grafana's database (users, folders, permissions) is backed up if it holds
  anything not in Git.
  **probe:** the Code probe above lists no UI-only dashboards; the object storage bucket has versioning on (provider
  guide). **(pause point)** in non-prod, rebuild the stack from Git and a restore, and open the main dashboards.
