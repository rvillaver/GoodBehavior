---
name: devops/helm
use-when: the project builds or deploys Helm charts; install next to the kubernetes guide
---

# Helm: rules for charts and releases, each with its probe

Probes are reads, renders or server-side dry runs unless marked **(pause point)**: those change the cluster and need
the user's yes first, per `devops.md`. Probes were run with Helm 3.18 against a local Kubernetes 1.35 cluster. Helm 4
renames a few flags (for example `--atomic` becomes `--rollback-on-failure`); check `helm <command> --help` for your
version. Point every command at the project's cluster (`KUBECONFIG=files/kubeconfig`, see `kubernetes.md`).

## Charts

- **rule:** Charts follow the standard layout (`Chart.yaml`, `values.yaml`, `templates/`, `templates/_helpers.tpl`)
  and every object carries the recommended labels from a shared helper.
  **probe:** `helm lint --strict <chart>` passes;
  `helm template <release> <chart> | yq -r 'select(.metadata.labels["app.kubernetes.io/managed-by"] != "Helm") | .kind'`
  lists no object kinds.
- **rule:** `values.schema.json` checks the values (types, required keys, allowed values), so a typo fails before it
  reaches the cluster.
  **probe:** `helm lint --strict <chart> --set replicaCount=abc` fails with a schema error.
- **rule:** Safe defaults in `values.yaml`: resource requests and a memory limit, readiness probes, a non-root,
  read-only, all-capabilities-dropped `securityContext`, and the image pinned by digest. The rendered chart passes
  the `restricted` Pod Security level.
  **probe:** render and dry-run into a namespace labeled `pod-security.kubernetes.io/enforce=restricted` and
  `pod-security.kubernetes.io/warn=restricted`:
  `helm template <release> <chart> -n <ns> | kubectl apply --dry-run=server -n <ns> -f -` prints no
  `would violate PodSecurity` warnings and no `violates PodSecurity` errors. (Enforce rejects bare Pods; for
  Deployments and other controllers it only warns, and only with the `warn` label set.)
- **rule:** No secrets in the chart or in values files. Templates reference an existing Secret or an
  `ExternalSecret`; the values hold only its name.
  **probe:** `grep -rniE '(password|token|secret|apikey)\s*:\s*[^ {]' <chart>/values*.yaml` finds only references
  (names, empty strings); `gitleaks detect` on the repo finds nothing.
- **rule:** Dependencies are pinned to exact versions and `Chart.lock` is committed.
  **probe:** `helm dependency list <chart>` shows every dependency `ok`; `grep -nE 'version:\s*["'\'']?[~^*><]' <chart>/Chart.yaml`
  prints nothing.
- **rule:** Every chart change bumps the chart `version` (SemVer), and `appVersion` tracks the application.
  **probe:** in CI, `ct lint --target-branch main` (chart-testing) fails when templates changed without a version
  bump.
- **rule:** Rendered output is scanned like any other manifest.
  **probe:** `helm template <release> <chart> > rendered.yaml && trivy config --severity HIGH,CRITICAL rendered.yaml`
  reports nothing unexplained.

## Releases

- **rule:** Preview every upgrade before running it.
  **probe:** `helm template <release> <chart> -n <ns> -f <values-file> | kubectl diff -n <ns> -f -` (or `helm diff upgrade`
  with the helm-diff plugin) shows exactly the expected changes.
- **rule:** Upgrades wait for readiness and roll back on failure, with bounded history:
  `helm upgrade --install <release> <chart> -n <ns> -f <values-file> --atomic --wait --timeout 10m --history-max 10`.
  **probe:** **(pause point)** that command, after the user has seen the diff above.
- **rule:** No release is stuck half-done (`pending-install`, `pending-upgrade`, `failed`).
  **probe:** `helm list -A --pending` and `helm list -A --failed` list no releases (only the header);
  `helm history <release> -n <ns>`
  ends in `deployed`. Fixing a stuck release is a **(pause point)**:
  `helm rollback <release> <revision> -n <ns>`.
- **rule:** Environment values live in files (`values-prod.yaml`), reviewed in Git. No `--set` for production and
  no `--reuse-values` (it silently drops new chart defaults).
  **probe:** read the pipeline or GitOps config: values come from files; neither flag appears.
- **rule:** Production releases go through GitOps (Argo CD, or Flux `HelmRelease`), not a laptop.
  **probe:** `kubectl get helmreleases -A` (Flux) or `kubectl get applications -A` (Argo CD) shows the release synced.
- **rule:** Remember Helm keeps each release's values in a Secret in the release namespace
  (`sh.helm.release.v1.<release>.v<n>`). Anyone who can read Secrets there can read the values; limit that with RBAC.
  **probe:** `kubectl get secrets -n <ns> -l owner=helm` lists them (names only);
  `kubectl auth can-i get secrets -n <ns> --as=system:serviceaccount:<ns>:<serviceaccount>` is `no` for workloads.

## Supply chain

- **rule:** Third-party charts come from a trusted repository at a pinned version, are verified, and are rendered
  and read before first install.
  **probe:** `helm pull <repo>/<chart> --version <version> --verify` (provenance) or `cosign verify` for an OCI chart;
  `helm template` of it is scanned as above.
- **rule:** Your own charts are published to an OCI registry and signed.
  **probe:** `cosign verify <registry>/<path>/<chart>:<version>` passes for the published chart. The CI job
  publishes it; running that by hand is a **(pause point)**: `helm push <chart>-<version>.tgz oci://<registry>/<path>`.
