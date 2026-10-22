---
name: devops/ci
use-when: the project has CI/CD pipelines as code (GitHub Actions, Gitea Actions, GitLab CI); install next to the baseline
---

# CI pipelines: rules for safe, fast and cheap pipelines, each with its probe

The baseline covers the core (plan on PR, OIDC, protected prod, pinned actions, untrusted input). This guide adds
the rest. Probes marked "tested" were run in October 2026 with yq 4.54 and zizmor 1.30 on sample GitHub workflows;
Gitea Actions uses the same format, so they work on `.gitea/workflows` too. Set `<workflow-dir>` to the project's
folder. Every probe reads files only.

## Safety

- **rule:** Workflows pass actionlint and zizmor (GitHub and Gitea format).
  **probe:** `actionlint` and `zizmor --offline <workflow-dir>` print no findings, or each has a written reason
  (tested: zizmor flagged a `pull_request_target` trigger, persisted checkout credentials and broad permissions).
- **rule:** Code from a fork never runs with secrets: no `pull_request_target` (or `workflow_run`) job that checks
  out the pull request's code.
  **probe:** `grep -lE 'pull_request_target|workflow_run' <workflow-dir>/*.y*ml`; for each file, no checkout of
  `github.event.pull_request.head` (zizmor `dangerous-triggers`, tested).
- **rule:** Each job declares the smallest `permissions:` it needs, and checkout doesn't persist the token
  (`persist-credentials: false`) unless a later step pushes.
  **probe:** zizmor `excessive-permissions` and `artipacked` don't appear (tested).
- **rule:** Deploy jobs run in a named environment with protection rules, and prod secrets belong to that
  environment, not the whole repo.
  **probe:** deploy-like jobs without an environment (tested):
  `for f in <workflow-dir>/*.y*ml; do yq -r '.jobs | to_entries | .[] | select(.key | test("deploy|release|apply")) | select(.value.environment == null) | "'"$f"': " + .key' "$f"; done`
  prints nothing.

## Speed and cost

- **rule:** Every job has a timeout, so a hung job doesn't burn runner minutes for hours (GitHub's default is six
  hours).
  **probe:** jobs with no `timeout-minutes` (tested):
  `for f in <workflow-dir>/*.y*ml; do yq -r '.jobs | to_entries | .[] | select(.value["timeout-minutes"] == null) | "'"$f"': " + .key' "$f"; done`
  prints nothing.
- **rule:** A new push cancels the older run of the same pull request (`concurrency` with
  `cancel-in-progress: true`). Deploy workflows queue instead of cancelling, so an apply is never cut off halfway.
  **probe:** `for f in <workflow-dir>/*.y*ml; do printf '%s: %s\n' "$f" "$(yq -r '.concurrency.group // "none"' "$f")"; done`
  (tested); PR workflows show a group, deploy workflows have `cancel-in-progress: false`.
- **rule:** Dependencies and build layers are cached (the `setup-*` actions' `cache:`, `actions/cache`, Docker
  layer cache), and workflows run only when relevant files change (`paths:` filters).
  **probe:** `grep -nE 'cache:|actions/cache|cache-from' <workflow-dir>/*.y*ml` and
  `yq -r '.on.push.paths // .on.pull_request.paths // "all files"' <workflow-dir>/<file>`; compare a cached and an
  uncached run's duration in the CI history.
- **rule:** Self-hosted runners scale to zero when idle, and the runner bill is known per month.
  **probe:** read the runner pool's autoscaler settings (minimum 0, or a schedule) and last month's runner cost
  (the hosted CI bill, or the runner nodes in the cloud bill).
- **rule:** Artifacts and caches expire.
  **probe:** `grep -nE 'retention-days' <workflow-dir>/*.y*ml` on every upload step, or a repository default
  retention in the CI settings.
