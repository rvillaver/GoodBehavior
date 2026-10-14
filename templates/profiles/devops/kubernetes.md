---
name: devops/kubernetes
use-when: the project runs workloads on Kubernetes (managed EKS/AKS/GKE/DOKS or self-managed); install next to the baseline and the provider guide
---

# Kubernetes: rules for clusters and workloads, each with its probe

Every probe is a read, or a **server-side dry run** (`--dry-run=server`): the API server runs admission and validation
and returns the result, but stores nothing. Probes marked **(pause point)** change something and need the user's yes
first, per `devops.md`. Probes were run against a local Kubernetes 1.35 cluster.

Probes on add-ons (External Secrets, Kyverno, Gatekeeper, Gateway API, cert-manager, Argo CD, Flux) fail with
`the server doesn't have a resource type …` when the add-on isn't installed: that is a finding, not a broken probe.
`kubectl top` needs metrics-server; "Metrics API not available" is a finding too.

Before any probe, confirm which cluster you are talking to, and say it in the result:
`kubectl config current-context` and `kubectl cluster-info`. A shared kubeconfig often holds production contexts next to
local ones; use the project's `files/kubeconfig` (see Access) and pass `--context <name>` rather than trusting the
current one.

## Access

- **rule:** Keep the project's kubeconfig at `files/kubeconfig` in the project folder (or, for several clusters, one
  file per cluster in a `files/.kubeconfig/` folder), holding only this project's clusters, and list it in
  `.gitignore`. Point every command at it (`export
  KUBECONFIG=$PWD/files/kubeconfig`, or `--kubeconfig files/kubeconfig`), so nothing can reach a cluster from another
  project, such as a production context in `~/.kube/config`. Never print it: it holds cluster credentials.
  **probe:** `git check-ignore files/kubeconfig` prints the path; `stat -f '%Lp' files/kubeconfig` (macOS) or
  `stat -c '%a' files/kubeconfig` (Linux) prints `600` (for a folder, `ls -l files/.kubeconfig/` shows `-rw-------`
  on every file);
  `KUBECONFIG=files/kubeconfig kubectl config get-contexts -o name` lists only this project's clusters.

## Cluster and upgrades

- **rule:** The cluster runs a supported minor version. Kubernetes ships a minor release about every four months and
  supports each for about 14 months; stay within two minors of the latest.
  **probe:** `kubectl version -o json | jq -r .serverVersion.gitVersion`, compared with the current release list.
- **rule:** No deprecated or removed APIs in manifests or the cluster, checked before every upgrade.
  **probe:** `pluto detect-files -d <manifests-dir>` and `pluto detect-helm --output wide` (or `kubent`); nothing is
  listed as removed in the target version.
- **rule:** Control-plane certificates don't expire unnoticed (self-managed, kubeadm).
  **probe:** on a control-plane node, `sudo kubeadm certs check-expiration`; every certificate has months left and a
  renewal is scheduled. Managed clusters rotate these for you.
- **rule:** etcd is backed up before control-plane changes, and Secrets are encrypted at rest with a KMS provider.
  **probe:** self-managed: the API server runs with `--encryption-provider-config`, and the latest etcd snapshot is
  recent. Managed: the provider's encryption setting (for example `aws eks describe-cluster --name <cluster> --query cluster.encryptionConfig`).
- **rule:** Cluster-critical add-ons run with a system priority class so they aren't evicted first.
  **probe:** `kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,PRIORITY:.spec.priorityClassName`
  shows `system-cluster-critical` or `system-node-critical` for DNS, metrics and networking add-ons.
- **rule:** Nodes and control plane span at least three zones where availability matters; stay inside the
  documented limits (110 pods per node, 5,000 nodes, 150,000 pods, 300,000 containers).
  **probe:** `kubectl get nodes -L topology.kubernetes.io/zone` shows nodes in each zone;
  `kubectl get pods -A --field-selector=status.phase=Running -o name | wc -l` stays far below the limits.

## Namespaces and environments

- **rule:** Production gets its own cluster. Nothing runs in `default`; each team, environment or tenant has a
  namespace.
  **probe:** `kubectl get pods -n default` lists nothing; `kubectl get ns` shows named namespaces.
- **rule:** Each namespace has a `ResourceQuota` and a `LimitRange` so one team can't starve the rest.
  **probe:** `kubectl get resourcequota,limitrange -A`; every application namespace appears in both lists.

## Workloads

- **rule:** Every container has CPU and memory requests and a memory limit. CPU limits are optional. A typical web
  service starts around 100–200m CPU and 128–512Mi memory, then is tuned from real use.
  **probe:** containers missing them:
  `kubectl get pods -A -o json | jq -r '.items[] | .metadata.namespace as $n | .metadata.name as $p | .spec.containers[] | select(.resources.requests.cpu == null or .resources.requests.memory == null or .resources.limits.memory == null) | "\($n)/\($p) \(.name)"'`
  prints nothing for application namespaces.
- **rule:** Network-facing containers have a readiness probe; slow starters (over about 10 seconds) a startup probe;
  liveness probes only where a restart really fixes the failure.
  **probe:** `kubectl get pods -A -o json | jq -r '.items[] | .metadata.namespace as $n | .metadata.name as $p | .spec.containers[] | select(.readinessProbe == null) | "\($n)/\($p) \(.name)"'`.
- **rule:** Production workloads run at least two replicas, spread across zones, with a `PodDisruptionBudget`, and
  scale with an HPA. Run the VPA in recommendation mode (`updateMode: Off`) and apply its advice through code.
  **probe:** `kubectl get deploy -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,REPLICAS:.spec.replicas`,
  `kubectl get pdb -A`, `kubectl get hpa -A`; for spreading,
  `kubectl get deploy <name> -n <ns> -o jsonpath='{.spec.template.spec.topologySpreadConstraints}'` names
  `topology.kubernetes.io/zone`.
- **rule:** One container per pod, except a real sidecar (mesh proxy, log shipper) or an init container.
  **probe:** `kubectl get pods -A -o json | jq -r '.items[] | select((.spec.containers | length) > 1) | "\(.metadata.namespace)/\(.metadata.name): \([.spec.containers[].name] | join(","))"'`;
  each multi-container pod has a reason.
- **rule:** Images are pinned by digest (`@sha256:…`), never `:latest`, and built small (distroless or similar).
  **probe:** `kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u | grep -v '@sha256:'`
  prints nothing for application images.
- **rule:** Resources carry the recommended labels (`app.kubernetes.io/name`, `instance`, `version`, `component`,
  `part-of`, `managed-by`) plus owner, environment and cost center.
  **probe:** `kubectl get deploy -A -L app.kubernetes.io/name,app.kubernetes.io/managed-by,owner,environment`; no
  empty columns for application workloads.
- **rule:** Storage follows the pods' zones: zonal volumes bind where the pod lands.
  **probe:** `kubectl get storageclass -o custom-columns=NAME:.metadata.name,BINDING:.volumeBindingMode,ALLOWED:.allowedTopologies`;
  zonal classes use `WaitForFirstConsumer`.

## Security and attack surface

Assume the cluster is probed by automated tools: an exposed API server, kubelet or dashboard is found within hours.
Write findings in the "Security findings" format from `devops.md` (risk, how likely, impact, fix, evidence).

- **rule:** Pod Security Admission labels every namespace: `enforce` at the strictest level the workloads allow
  (`restricted` where possible, `privileged` only with a written reason), and `warn`/`audit` set to the level you
  are moving towards. An unlabeled namespace is an unreviewed one.
  **probe:** `kubectl get ns -L pod-security.kubernetes.io/enforce,pod-security.kubernetes.io/warn,pod-security.kubernetes.io/audit`;
  then prove it bites with a dry run that stores nothing:
  `kubectl run psa-probe --image=busybox --privileged --dry-run=server -n <ns> -- true` is rejected with
  `violates PodSecurity`. **Note:** `enforce` rejects Pods; Deployments and other controllers are only warned
  about, and only when the namespace also has a `warn` label, so their bad pods fail later, at creation.
- **rule:** Containers run as non-root, with a read-only root filesystem, no privilege escalation, all capabilities
  dropped, and `seccompProfile: RuntimeDefault`.
  **probe:** `kubectl get pods -A -o json | jq -r '.items[] | .metadata.namespace as $n | .metadata.name as $p | .spec.containers[] | select(.securityContext.runAsNonRoot != true or .securityContext.readOnlyRootFilesystem != true or .securityContext.allowPrivilegeEscalation != false) | "\($n)/\($p) \(.name)"'`
  prints nothing for application namespaces (or the pod-level `securityContext` covers it).
- **rule:** Least-privilege RBAC: no person or workload bound to `cluster-admin`; namespaced `Role`/`RoleBinding`
  over cluster-wide ones; service accounts don't mount tokens they don't use.
  **probe:** `kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | "\(.metadata.name): \([.subjects[]? | .kind + "/" + .name] | join(", "))"'`
  lists only system bindings; for a workload,
  `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<serviceaccount> -n <ns>` shows only what it needs.
- **rule:** Every namespace starts from default-deny ingress and egress, then allows only the flows it needs (DNS,
  its database, its upstream APIs). The network plugin must enforce NetworkPolicy.
  **probe:** `kubectl get networkpolicy -A`; each application namespace has a default-deny policy. **Note:** some
  plugins accept NetworkPolicy objects without enforcing them; confirm the CNI supports it.
- **rule:** Secrets come from an external secrets manager (a cloud secret manager, Vault or OpenBao) through
  External Secrets or the Secrets Store CSI driver, never from Git. Built-in `Secret` objects are base64, not
  encrypted, and `list` on Secrets reads all of them.
  **probe:** `kubectl get externalsecrets -A` or `kubectl get secretproviderclass -A` (whichever the cluster uses);
  `gitleaks detect` on the manifests repo finds nothing. Never print secret values: the guard denies dumping Secret
  objects as YAML or JSON.
- **rule:** If the cluster has no secrets manager, suggest **OpenBao** (open source, a Linux Foundation fork of
  Vault, same API). Run it from its Helm chart in HA mode with Raft storage, auto-unseal through a cloud KMS or a
  transit key, the Kubernetes auth method so workloads log in with their service account, and an audit device on.
  Feed workloads through External Secrets (its Vault provider works with OpenBao) or the OpenBao agent injector. This
  is a suggestion; a cloud secret manager or Vault serves the same rule.
  **probe:** `kubectl get pods -A -l app.kubernetes.io/name=openbao` shows the server pods running; inside one,
  `bao status` shows `Sealed false` and `HA Enabled true`; `bao auth list` includes `kubernetes/`;
  `bao audit list` shows a device. None of these print secret values.
- **rule:** An admission policy engine (Kyverno or Gatekeeper) enforces what PSA can't: signed images, required
  labels, allowed registries.
  **probe:** `kubectl get clusterpolicies` (Kyverno) or `kubectl get constrainttemplates` (Gatekeeper) lists the
  policies; a dry run of a non-compliant pod (`--dry-run=server`) is rejected.
- **rule:** Supply chain: images are scanned and fail the build on HIGH or CRITICAL findings; they carry an SBOM
  and a signature, and the cluster verifies the signature on admission.
  **probe:** `trivy image --severity HIGH,CRITICAL --exit-code 1 <image>`;
  `cosign verify --certificate-identity <identity> --certificate-oidc-issuer <issuer> <image>@sha256:<digest>`.
- **rule:** Traffic enters through the Gateway API (or a supported ingress controller), with TLS from cert-manager
  and a WAF in front. **Note:** ingress-nginx has been announced for retirement; check your
  controller is still maintained.
  **probe:** `kubectl get gateways,httproutes -A` (or `kubectl get ingress -A`) and `kubectl get certificates -A`
  (cert-manager); every certificate shows `READY True`.

- **rule:** The API server isn't open to the internet: a private endpoint, or a public one limited to known
  networks. Anonymous requests get nothing.
  **probe:** from outside the allowed networks, `curl -sk https://<api-server>/version` times out or is refused;
  `curl -sk -o /dev/null -w '%{http_code}\n' https://<api-server>/api/v1/namespaces` returns `401` or `403`. Managed
  clusters: `aws eks describe-cluster --name <cluster> --query 'cluster.resourcesVpcConfig.[endpointPublicAccess,publicAccessCidrs]'`,
  `az aks show -g <rg> -n <cluster> --query apiServerAccessProfile`,
  `gcloud container clusters describe <cluster> --project=<project> --format="yaml(masterAuthorizedNetworksConfig,privateClusterConfig)"`.
- **rule:** Kubelets don't answer anonymous requests, and the read-only port is closed.
  **probe:** from inside the cluster network, `nc -zv -w 3 <node-ip> 10255` fails and
  `curl -sk -o /dev/null -w '%{http_code}\n' https://<node-ip>:10250/pods` returns `401` or `403`.
- **rule:** API server audit logging is on and shipped off the cluster.
  **probe:** managed: `aws eks describe-cluster --name <cluster> --query cluster.logging` includes `audit`; AKS and
  GKE through their diagnostic/logging settings. Self-managed: the API server runs with `--audit-log-path` and an
  audit policy.
- **rule:** No one but system components holds RBAC rights that escalate: `*` verbs or resources, `escalate`, `bind`,
  `impersonate`, or reading Secrets cluster-wide.
  **probe:** cluster roles that grant them:
  `kubectl get clusterroles -o json | jq -r '.items[] | select(.metadata.name | startswith("system:") | not) | select(any(.rules[]?; ((.verbs // []) | index("*") or index("escalate") or index("bind") or index("impersonate")) or ((.resources // []) | index("secrets") or index("*")))) | .metadata.name'`,
  then `kubectl get clusterrolebindings,rolebindings -A -o wide` shows who holds each one; only admins and
  system components. The built-in `cluster-admin`, `admin` and `edit` roles always appear; the finding is who they
  are bound to.
- **rule:** Service accounts don't mount API tokens unless the workload calls the API.
  **probe:** `kubectl get serviceaccounts -A -o json | jq -r '.items[] | select(.automountServiceAccountToken != false) | "\(.metadata.namespace)/\(.metadata.name)"'`;
  each one listed needs the API.
- **rule:** Workloads get no host access: no `hostNetwork`, `hostPID`, `hostIPC`, `hostPath` or privileged containers
  outside system namespaces.
  **probe:** `kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork or .spec.hostPID or .spec.hostIPC or any(.spec.volumes[]?; .hostPath) or any(.spec.containers[]; .securityContext.privileged)) | "\(.metadata.namespace)/\(.metadata.name)"'`
  lists only system namespaces.
- **rule:** Pods can't reach the cloud metadata endpoint (169.254.169.254), which hands out node credentials: an
  egress NetworkPolicy blocks it, and on AWS the instance metadata hop limit is 1 with IMDSv2 required.
  **probe:** `aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions.[HttpTokens,HttpPutResponseHopLimit]'`
  shows `required` and `1`; **(pause point)** from an application namespace,
  `kubectl run imds-probe -n <ns> --rm -i --restart=Never --image=busybox:1.36 -- wget -T 3 -qO- http://169.254.169.254/`
  times out.
- **rule:** Only intended services are exposed: every `LoadBalancer` and `NodePort` service has a reason and, where
  possible, `loadBalancerSourceRanges`. Admin UIs (dashboards, Argo CD, Grafana) sit behind SSO, never open.
  **probe:** `kubectl get svc -A -o json | jq -r '.items[] | select(.spec.type == "LoadBalancer" or .spec.type == "NodePort") | "\(.metadata.namespace)/\(.metadata.name) \(.spec.type) \(.spec.loadBalancerSourceRanges // [] | join(","))"'`.
- **rule:** Security admission webhooks fail closed, so a webhook outage doesn't let everything through.
  **probe:** `kubectl get validatingwebhookconfigurations -o json | jq -r '.items[] | "\(.metadata.name): \([.webhooks[].failurePolicy] | join(","))"'`
  shows `Fail` for policy engines.
- **rule:** Runtime threat detection watches the nodes and containers (Falco, or the provider's: GuardDuty runtime
  monitoring, Defender for Containers, GKE threat detection), and its alerts reach a human.
  **probe:** `kubectl get daemonsets -A` shows the detection agent on every node, and a recent alert can be found.
- **rule:** The cluster is scanned against a benchmark (CIS, NSA/CISA) and for vulnerable images, on a schedule.
  **probe:** `trivy k8s --disable-node-collector --report summary`, `kubescape scan framework nsa`, or Prowler
  (`prowler kubernetes --kubeconfig-file <kubeconfig> --context <context> --severity critical high`); findings have
  owners. Running `kube-bench` as a Job on the nodes is a **(pause point)**.
- **rule:** Traffic between services is encrypted and authenticated where the data is sensitive (a service mesh in
  strict mTLS mode).
  **probe:** `kubectl get peerauthentication -A` (Istio) shows `STRICT`, or the mesh's equivalent.
- **rule:** Denial-of-service limits: `ResourceQuota` and `LimitRange` per namespace (see Namespaces), API Priority
  and Fairness on, rate limits and a WAF at the edge.
  **probe:** `kubectl get flowschemas` lists the default schemas; edge limits per the baseline Security section.

## Delivery

- **rule:** A GitOps controller (Argo CD, Flux) applies changes to production; people don't run `kubectl apply`
  there. Drift raises an alert and failed health checks roll back.
  **probe:** `kubectl get applications -A` (Argo CD) or `kubectl get kustomizations -A` (Flux) shows every app synced
  and healthy.
- **rule:** Manifests come from Helm, Kustomize or code (not copied YAML) and are validated before they reach the
  cluster.
  **probe:** `helm lint <chart>`, `helm template <chart> | kubectl apply --dry-run=server -f -`, and
  `kubectl diff -f <manifest>` show the change without applying it.
- **rule:** Treat clusters as cattle: fix things in code and let the controller redeploy; never hand-edit live
  objects. A cluster can be rebuilt from Git in about an hour.
  **probe:** `kubectl diff -f <manifests>` against the live cluster shows no unexplained differences (drift).

## Observability

- **rule:** Metrics, logs and traces are collected centrally; alerts fire on SLO burn rate, not every pod restart;
  logs are structured, kept for a set time, with secrets and personal data redacted at the collector.
  **probe:** `kubectl top nodes` works (metrics pipeline is up); the collector DaemonSet is running on every node:
  `kubectl get daemonset -A`.

## Cost

- **rule:** Requests match real use (VPA recommendations or Goldilocks), non-prod scales down off-hours, spot nodes
  run interruptible work, and cost is shown per namespace (OpenCost, Kubecost).
  **probe:** `kubectl top pods -A` compared with the requests from the Workloads probe; requests far above use are
  over-provisioned, use near limits is under-provisioned (see baseline Cost).
