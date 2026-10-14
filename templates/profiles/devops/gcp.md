---
name: devops/gcp
use-when: the project runs on Google Cloud; install next to the baseline
---

# Google Cloud: the baseline rules mapped to GCP services and CLI probes

Each rule points at its baseline rule (`baseline.md`) and gives the Google Cloud way to check it. All probes are
read-only unless marked **(pause point)**: those need the user's yes first, per `devops.md`. Replace `<...>` with
real values. Every command here was checked against Google Cloud SDK 588, GA commands only (command, flags and
required arguments). `--filter` and `--format` are applied after the call, so their syntax was reviewed by eye.

Before any probe, confirm which account and project you are using, and say it in the result:
`gcloud auth list --filter=status:ACTIVE --format="value(account)"` and `gcloud config get project`. Pass
`--project=<project>` on every call rather than trusting the default.

## IaC and state

- **rule:** The state bucket is versioned, private and uniform-access (baseline: state is remote, encrypted,
  versioned).
  **probe:** `gcloud storage buckets describe gs://<state-bucket> --format="yaml(versioning_enabled,public_access_prevention,uniform_bucket_level_access,default_kms_key)"`
  shows versioning on and public access prevention `enforced`. Locking: the `gcs` backend locks on its own.
- **rule:** Each environment is its own project, so a dev identity can't reach prod (baseline: separate state and
  credentials).
  **probe:** as the dev identity, `gcloud storage ls gs://<prod-state-bucket>` fails with 403.
- **rule:** No console changes outside code (baseline: everything in code).
  **probe:** Admin Activity audit logs hold writes only:
  `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"' --project=<project> --freshness=7d --limit=50 --format="table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.methodName)"`;
  any principal that isn't the pipeline needs an owner and a code change.

## CI/CD

- **rule:** The pipeline uses Workload Identity Federation, not a service account key (baseline: short-lived
  credentials).
  **probe:** `gcloud iam workload-identity-pools providers describe <provider> --workload-identity-pool=<pool> --location=global --project=<project> --format="value(attributeCondition)"`
  restricts to this repo; `gcloud iam service-accounts keys list --iam-account=<sa-email> --managed-by=user --project=<project>`
  is empty.
- **rule:** Only the protected branch or environment can deploy to prod (baseline: prod deploys gated).
  **probe:** the prod provider's `attributeCondition` (same call) names the protected branch or environment, not
  just the repository.

## Secrets and identity

- **rule:** Secrets live in Secret Manager and rotate (baseline: secret manager, rotation).
  **probe:** `gcloud secrets list --project=<project> --format="table(name,rotation.nextRotationTime,replication)"`;
  each secret has a rotation schedule or a written reason.
- **rule:** Workloads run as their own service account, not the default compute account (baseline: workload
  identity).
  **probe:** `gcloud compute instances list --project=<project> --format="table(name,serviceAccounts[].email)"` shows
  no `-compute@developer.gserviceaccount.com`. From inside the workload,
  `curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email`
  returns the expected account. On GKE, use Workload Identity.
- **rule:** Least privilege: no basic roles (`owner`, `editor`) for workloads (baseline: each identity can do its
  job and nothing more).
  **probe:** `gcloud projects get-iam-policy <project> --flatten="bindings[].members" --filter="bindings.role:(roles/owner OR roles/editor)" --format="table(bindings.role,bindings.members)"`
  lists only named humans or break-glass. Ask IAM without changing anything:
  `gcloud policy-troubleshoot iam //storage.googleapis.com/projects/_/buckets/<other-bucket> --principal-email=<sa-email> --permission=storage.objects.delete`
  shows the access as denied.
- **rule:** Humans sign in with 2-step verification enforced (baseline: SSO, MFA). This is set in the Google
  Workspace or Cloud Identity admin console, not in `gcloud`.
  **probe:** check the admin console's 2-step verification enforcement for the groups that hold project roles.

## Networking

- **rule:** No admin or database ports open to the internet (baseline: ingress limited).
  **probe:** `gcloud compute firewall-rules list --project=<project> --filter="direction=INGRESS AND sourceRanges:0.0.0.0/0 AND disabled=false" --format="table(name,network,allowed[].map().firewall_rule().list())"`
  shows only 80/443.
- **rule:** Databases and buckets are not public (baseline: nothing public unless meant to be).
  **probe:** `gcloud sql instances list --project=<project> --format="table(name,settings.ipConfiguration.ipv4Enabled,settings.ipConfiguration.authorizedNetworks[].value)"`
  shows no public IP, or no `0.0.0.0/0` authorized network;
  `gcloud storage buckets list --project=<project> --format="table(name,public_access_prevention)"`.
- **rule:** Certificates are Google-managed and renew on their own (baseline: TLS renewed automatically).
  **probe:** `gcloud compute ssl-certificates list --project=<project> --format="table(name,type,managed.status,expireTime)"`
  or `gcloud certificate-manager certificates list --project=<project>`. Then `openssl s_client` from outside.
- **rule:** Cloud DNS matches what resolves (baseline: DNS in code, resolves as intended).
  **probe:** `gcloud dns record-sets list --zone=<zone-name> --project=<project> --format="table(name,type,rrdatas)"`,
  compared with `dig +short <name>` from outside and from inside the VPC.
- **rule:** Egress goes through Cloud NAT with known addresses (baseline: known outbound path).
  **probe:** `gcloud compute routers nats list --router=<router> --region=<region> --project=<project>` and
  `gcloud compute addresses list --project=<project> --format="table(name,address,purpose,status)"`; the NAT
  address matches `curl -s https://ifconfig.me` from the workload.

## Observability

- **rule:** Audit logs are kept in a locked log bucket (baseline: audit log on and protected). Admin Activity logs
  are always on; Data Access logs are opt-in.
  **probe:** `gcloud logging buckets list --location=global --project=<project> --format="table(name,retentionDays,locked)"`
  and `gcloud projects get-iam-policy <project> --format="yaml(auditConfigs)"` for Data Access logs.
- **rule:** Logs have a set retention (baseline: central logs with a set retention).
  **probe:** the `retentionDays` column above; `gcloud logging sinks list --project=<project>` shows where logs go.
- **rule:** Alerts exist and reach a human (baseline: alerts reach a human).
  **probe:** `gcloud monitoring policies list --project=<project> --format="table(displayName,enabled,notificationChannels.len())"`;
  every policy has a channel. **(pause point)** to test, fire a non-prod alert and confirm it arrives.
- **rule:** Public endpoints have an uptime check (baseline: uptime probe from outside).
  **probe:** `gcloud monitoring uptime list-configs --project=<project>`.

## Security and attack surface

- **rule:** Public apps sit behind Cloud Armor with preconfigured WAF rules (SQL injection, XSS), rate limiting and
  bot management, and Adaptive Protection on (baseline: WAF, injection, bots, rate limits).
  **probe:** `gcloud compute security-policies list --project=<project>`;
  `gcloud compute security-policies describe <policy> --project=<project> --format="yaml(rules[].match.expr,rules[].action,adaptiveProtectionConfig)"`
  shows `evaluatePreconfiguredWaf('sqli-...')`-style rules, a `rate_based_ban` or `throttle` rule, and adaptive
  protection enabled.
- **rule:** Every public backend has a security policy, and nothing bypasses the load balancer (baseline: origin
  locked).
  **probe:** `gcloud compute backend-services list --project=<project> --format="table(name,securityPolicy)"` has no
  empty `securityPolicy`; VMs have no external IPs unless needed:
  `gcloud compute instances list --project=<project> --format="table(name,networkInterfaces[].accessConfigs[].natIP)"`.
- **rule:** TLS 1.2+ with a modern SSL policy (baseline: TLS).
  **probe:** `gcloud compute ssl-policies list --project=<project> --format="table(name,minTlsVersion,profile)"`
  shows `TLS_1_2` and the policy is attached to each HTTPS proxy
  (`gcloud compute target-https-proxies list --project=<project> --format="table(name,sslPolicy)"`).
- **rule:** Admin access through IAP TCP forwarding or OS Login, not open SSH or RDP (baseline: admin access never
  public).
  **probe:** the firewall probe in Networking shows no 22 or 3389 from `0.0.0.0/0`; an IAP rule allows
  `35.235.240.0/20` instead.
- **rule:** VMs use OS Login and Shielded VM, so SSH keys aren't scattered in metadata and boot tampering is caught
  (baseline: admin access never public, SSO with MFA).
  **probe:** `gcloud compute project-info describe --project=<project> --format="yaml(commonInstanceMetadata.items)"`
  shows `key: enable-oslogin` with `value: 'TRUE'`;
  `gcloud compute instances list --project=<project> --format="table(name,shieldedInstanceConfig.enableSecureBoot,shieldedInstanceConfig.enableVtpm,shieldedInstanceConfig.enableIntegrityMonitoring)"`
  shows `True` for each.
- **rule:** The whole project is scanned against a standard, not only the services this guide names (baseline: know
  the whole attack surface).
  **probe:** Prowler (open source, read-only API calls; tested with 5.44), signed in with
  application-default credentials (gcloud auth application-default login):
  `prowler gcp --project-id <project> --severity critical high --output-formats csv html`, and for card data add
  `--compliance pci_4.0_gcp`. Every FAIL is a finding or has a written reason.
- **rule:** Security Command Center is on and read (baseline: detection and vulnerability scanning).
  **probe:** `gcloud scc findings list projects/<project> --filter="state=\"ACTIVE\" AND severity=\"CRITICAL\""`
  has owners for every finding; container image vulnerabilities via
  `gcloud artifacts docker images describe <image> --show-package-vulnerability`.

## Backup and DR

- **rule:** Databases and disks have automated backups (baseline: automated backups).
  **probe:** `gcloud sql instances describe <instance> --project=<project> --format="yaml(settings.backupConfiguration)"`
  shows backups and point-in-time recovery on; `gcloud sql backups list --instance=<instance> --project=<project> --limit=5`;
  disk snapshot schedules `gcloud compute resource-policies list --project=<project>` and
  `gcloud compute snapshots list --project=<project> --format="table(name,sourceDisk,creationTimestamp)"`.
- **rule:** Restores are tested (baseline: a backup never restored doesn't count).
  **probe:** **(pause point)** clone into a new, separately named instance:
  `gcloud sql instances clone <instance> <instance>-restore-test --point-in-time=<iso-time> --project=<project>`,
  check the data, record the time taken, then delete the clone (also a pause point).
- **rule:** Backups survive a compromised project: Backup and DR vaults with enforced retention, or copies in
  another project or region (baseline: protected from the account).
  **probe:** `gcloud backup-dr backup-vaults list --location=<region> --project=<project>`, and the Cloud SQL
  backup location in `settings.backupConfiguration.location` (from the describe call above).
- **rule:** High availability works where the design claims it (baseline: failover tested).
  **probe:** `gcloud sql instances describe <instance> --project=<project> --format="value(settings.availabilityType)"`
  is `REGIONAL` where HA is claimed. **(pause point)** in non-prod:
  `gcloud sql instances failover <instance> --project=<project>` and time the recovery.

## Cost

- **rule:** Required labels on everything (baseline: tags enforced).
  **probe:** `gcloud asset search-all-resources --scope=projects/<project> --filter="-labels.owner:*" --format="table(name,assetType)"`
  is empty (needs the Cloud Asset API).
- **rule:** Budgets with alerts (baseline: budgets per project and environment).
  **probe:** `gcloud billing budgets list --billing-account=<billing-account-id>`.
- **rule:** No idle spend (baseline: no idle resources).
  **probe:** unattached disks `gcloud compute disks list --project=<project> --filter="-users:*" --format="table(name,zone,sizeGb)"`;
  reserved but unused addresses `gcloud compute addresses list --project=<project> --filter="status=RESERVED"`;
  stopped VMs that still pay for disks `gcloud compute instances list --project=<project> --filter="status=TERMINATED"`;
  idle VMs `gcloud recommender recommendations list --project=<project> --location=<zone> --recommender=google.compute.instance.IdleResourceRecommender`.
- **rule:** Sized from real use (baseline: not over-provisioned).
  **probe:** `gcloud recommender recommendations list --project=<project> --location=<zone> --recommender=google.compute.instance.MachineTypeRecommender --format="table(description,primaryImpact.category)"`.
  Memory-based advice needs the Ops Agent on the VM.
- **rule:** Not running hot (baseline: not under-provisioned).
  **probe:** the same machine-type recommender also suggests bigger sizes for VMs that run hot; check managed
  instance groups pinned at their maximum with
  `gcloud compute instance-groups managed list --project=<project> --format="table(name,size,autoscaled)"` and the
  autoscaler limits in the console or Terraform.
- **rule:** Redundancy matches the target (baseline: redundancy vs availability target).
  **probe:** `gcloud sql instances list --project=<project> --format="table(name,settings.availabilityType,settings.tier)"`
  (`REGIONAL` in dev is usually waste); bucket locations
  `gcloud storage buckets list --project=<project> --format="table(name,location,location_type)"` (multi-region for
  dev data is usually waste); matched against each environment's availability target.
- **rule:** Pricing model fits use (baseline: commitments, spot, newer generations). GCP extras: sustained-use
  discounts apply on their own to some machine families; Spot VMs for interruptible work.
  **probe:** `gcloud compute commitments list --project=<project>`; machine types in use
  `gcloud compute instances list --project=<project> --format="table(name,machineType.basename(),scheduling.provisioningModel)"`,
  looking for older families where E2, N4 or Arm (`C4A`, `T2A`) fits.
- **rule:** Storage in the right tier (baseline: lifecycle, retention, disk type).
  **probe:** `gcloud storage buckets describe gs://<bucket> --format="yaml(lifecycle_config,default_storage_class)"`;
  disks `gcloud compute disks list --project=<project> --format="table(name,type.basename(),sizeGb,provisionedIops)"`
  (`pd-ssd` or high provisioned IOPS in dev is usually waste).
- **rule:** Data transfer is known (baseline: data transfer kept low).
  **probe:** export billing to BigQuery and group by SKU for network egress; check Private Google Access is on for
  subnets that call Google APIs:
  `gcloud compute networks subnets list --project=<project> --format="table(name,region,privateIpGoogleAccess)"`.
