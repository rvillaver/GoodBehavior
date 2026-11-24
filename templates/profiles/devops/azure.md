---
name: devops/azure
use-when: the project runs on Azure; install next to the baseline
---

# Azure: the baseline rules mapped to Azure services and CLI probes

Each rule points at its baseline rule (`baseline.md`) and gives the Azure way to check it. All probes are read-only
unless marked **(pause point)**: those need the user's yes first, per `devops.md`. Replace `<...>` with real values.
Every command here was checked against Azure CLI 2.89, core commands only, no extensions (command, arguments and
`--query` syntax).

Before any probe, confirm which tenant and subscription you are in, and say it in the result:
`az account show --query "{subscription:name,id:id,tenant:tenantId,user:user.name}"`.

## IaC and state

- **rule:** The state storage account is HTTPS-only, private, with blob versioning and soft delete (baseline:
  state is remote, encrypted, versioned).
  **probe:** `az storage account show -n <state-account> -g <rg> --query "{httpsOnly:enableHttpsTrafficOnly,publicBlob:allowBlobPublicAccess,tls:minimumTlsVersion,network:publicNetworkAccess}"`
  and `az storage account blob-service-properties show --account-name <state-account> -g <rg> --query "{versioning:isVersioningEnabled,softDelete:deleteRetentionPolicy.enabled}"`.
  Locking: the `azurerm` backend locks with blob leases on its own.
- **rule:** Each environment is its own subscription, so a dev identity can't reach prod (baseline: separate state
  and credentials).
  **probe:** signed in as the dev identity, `az storage blob list --account-name <prod-state-account> --container-name <container> --auth-mode login`
  fails with `AuthorizationPermissionMismatch`.
- **rule:** No portal changes outside code (baseline: everything in code).
  **probe:** the Activity Log holds writes only:
  `az monitor activity-log list --offset 7d --query "[].{time:eventTimestamp,caller:caller,op:operationName.value}" -o table`;
  any caller that isn't the pipeline identity needs an owner and a code change.

## CI/CD

- **rule:** The pipeline uses workload identity federation (OIDC), not a client secret (baseline: short-lived
  credentials).
  **probe:** `az ad app federated-credential list --id <app-id> --query "[].{subject:subject,issuer:issuer}"` shows a
  subject scoped to this repo and branch or environment; `az ad app credential list --id <app-id>` is empty.
- **rule:** Only the protected branch or environment can deploy to prod (baseline: prod deploys gated).
  **probe:** the prod app's federated credential `subject` names the protected environment (for example
  `repo:<org>/<repo>:environment:prod`), never a pull-request or wildcard subject.

## Secrets and identity

- **rule:** Key inventory: every sensitive key is in Key Vault, and apps reference it instead of holding the value
  (baseline: key inventory).
  **probe:** names only. Vault contents: `az keyvault secret list --vault-name <vault> --query "[].{name:name,enabled:attributes.enabled,expires:attributes.expires}" -o table`.
  App Service and Functions settings, plain vs Key Vault reference:
  `az webapp config appsettings list -g <rg> -n <app> --query "[].{name:name,keyVaultRef:starts_with(value, '@Microsoft.KeyVault')}" -o table`
  (`az functionapp config appsettings list -g <rg> -n <app>` for function apps, with the same `--query`). Container Apps: `az containerapp show -g <rg> -n <app> --query "properties.template.containers[].env[].{name:name,secretRef:secretRef}" -o table`.
  A sensitive name with `keyVaultRef` false, or no `secretRef`, is a finding.
- **rule:** Secrets live in Key Vault with soft delete, purge protection and RBAC, not public (baseline: secret
  manager).
  **probe:** `az keyvault show -n <vault> --query "properties.{softDelete:enableSoftDelete,purgeProtection:enablePurgeProtection,rbac:enableRbacAuthorization,publicAccess:publicNetworkAccess}"`.
- **rule:** Secrets and keys expire or rotate (baseline: rotation).
  **probe:** `az keyvault secret list --vault-name <vault> --query "[].{name:name,expires:attributes.expires}" -o table`
  and `az keyvault key rotation-policy show --vault-name <vault> -n <key>`.
- **rule:** Workloads use managed identities, not stored credentials (baseline: workload identity).
  **probe:** `az vm identity show -g <rg> -n <vm>` or `az webapp identity show -g <rg> -n <app>` shows a principal ID.
  From inside the workload (it only works there), `az login --identity` then `az account show --query user` shows a managed identity, not
  a user.
- **rule:** Least privilege (baseline: each identity can do its job and nothing more).
  **probe:** `az role assignment list --assignee <principal-id> --all --query "[].{role:roleDefinitionName,scope:scope}" -o table`;
  no `Owner` or `Contributor` at subscription scope for a workload.
- **rule:** Few owners, all with MFA through Conditional Access (baseline: SSO, MFA, owners locked down).
  **probe:** `az role assignment list --role Owner --scope /subscriptions/<subscription-id> --query "[].principalName"`
  is short and named; `az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies --query "value[].{name:displayName,state:state}"`
  shows an enabled MFA policy.

## Networking

- **rule:** No admin or database ports open to the internet (baseline: ingress limited).
  **probe:** `az network nsg list --query "[].{nsg:name,open:securityRules[?access=='Allow' && direction=='Inbound' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')].destinationPortRange}"`
  shows only 80/443.
- **rule:** Databases and storage are not public (baseline: nothing public unless meant to be).
  **probe:** `az sql server list --query "[].{name:name,public:publicNetworkAccess}"`,
  `az postgres flexible-server list --query "[].{name:name,public:network.publicNetworkAccess}"`,
  `az storage account list --query "[].{name:name,publicBlob:allowBlobPublicAccess,network:publicNetworkAccess}"`.
- **rule:** Certificates renew on their own (baseline: TLS renewed automatically).
  **probe:** `az keyvault certificate list --vault-name <vault> --query "[].{name:name,expires:attributes.expires}" -o table`;
  each has an auto-renew policy (`az keyvault certificate show --vault-name <vault> -n <cert> --query policy.lifetimeActions`).
  Then `openssl s_client` from outside, per baseline.
- **rule:** DNS in Azure DNS matches what resolves (baseline: DNS in code, resolves as intended).
  **probe:** `az network dns record-set list -g <rg> -z <zone> --query "[].{name:fqdn,type:type}" -o table` and
  `az network private-dns record-set list -g <rg> -z <private-zone> -o table`, compared with `dig +short <name>` from
  outside and from inside the VNet.
- **rule:** Egress goes through a NAT gateway or Azure Firewall with known addresses (baseline: known outbound
  path).
  **probe:** `az network nat gateway list --query "[].{name:name,ips:publicIpAddresses[].id}"`, then
  `az network public-ip show --ids <public-ip-id> --query ipAddress`; it matches `curl -s https://ifconfig.me` from
  the workload.

## Observability

- **rule:** The Activity Log is exported and kept (baseline: audit log on and protected).
  **probe:** `az monitor diagnostic-settings subscription list --query "value[].{name:name,workspace:workspaceId,storage:storageAccountId}"`
  shows an export to a workspace or a locked storage account.
- **rule:** Log Analytics has a set retention (baseline: central logs with a set retention).
  **probe:** `az monitor log-analytics workspace show -g <rg> -n <workspace> --query retentionInDays`.
- **rule:** Alerts exist and reach a human (baseline: alerts reach a human).
  **probe:** `az monitor metrics alert list --query "[?!actions].name"` is empty (every alert has an action group);
  `az monitor action-group list --query "[].{name:name,email:emailReceivers[].emailAddress}"`. **(pause point)** to
  test, fire a non-prod alert and confirm it arrives.
- **rule:** Public endpoints have an outside availability test (baseline: uptime probe from outside).
  **probe:** `az resource list --resource-type Microsoft.Insights/webtests --query "[].name"`.

## Security and attack surface

- **rule:** Public apps sit behind a WAF (Front Door or Application Gateway) with the managed OWASP/default rule set,
  bot protection and rate limits, in Prevention mode (baseline: WAF, injection, bots, rate limits).
  **probe:** `az network application-gateway waf-policy list -g <rg> --query "[].{name:name,mode:policySettings.mode,rules:managedRules.managedRuleSets[].ruleSetType}"`;
  Front Door policies: `az resource list --resource-type Microsoft.Network/FrontDoorWebApplicationFirewallPolicies --query "[].id" -o tsv`,
  then `az resource show --ids <policy-id> --query "properties.{mode:policySettings.mode,state:policySettings.enabledState,rules:managedRules.managedRuleSets[].ruleSetType}"`.
  Mode is `Prevention`, not `Detection`.
- **rule:** Nothing public bypasses the WAF: app services and VMs accept traffic only from Front Door or the
  Application Gateway (baseline: origin locked).
  **probe:** `az webapp config access-restriction show -g <rg> -n <app>` allows only the `AzureFrontDoor.Backend`
  service tag (with the Front Door ID header check); public IPs `az network public-ip list --query "[].{name:name,ip:ipAddress,attachedTo:ipConfiguration.id}" -o table`
  each has a reason.
- **rule:** DDoS protection fits the risk: basic protection is automatic; DDoS Network Protection for
  business-critical virtual networks (baseline: DDoS limits).
  **probe:** `az network ddos-protection list --query "[].{name:name,vnets:virtualNetworks[].id}"`.
- **rule:** TLS 1.2+ everywhere (baseline: TLS).
  **probe:** `az webapp config show -g <rg> -n <app> --query "{minTls:minTlsVersion,ftps:ftpsState,httpsOnly:httpsOnly}"`
  and the storage `minimumTlsVersion` from the Networking probe show `1.2`.
- **rule:** Admin access through Azure Bastion or just-in-time access, not open SSH or RDP (baseline: admin access
  never public).
  **probe:** `az resource list --resource-type Microsoft.Network/bastionHosts --query "[].name"`; the NSG probe in Networking shows no 22 or 3389 open to
  the internet.
- **rule:** The whole subscription is scanned against a standard, not only the services this guide names
  (baseline: know the whole attack surface).
  **probe:** Prowler (open source, read-only API calls; tested with 5.44), signed in with az login:
  `prowler azure --az-cli-auth --subscription-ids <subscription-id> --severity critical high --output-formats csv html`,
  and for card data add `--compliance pci_4.0_azure`. Every FAIL is a finding or has a written reason.
- **rule:** Microsoft Defender for Cloud is on and read (baseline: detection and vulnerability scanning).
  **probe:** `az security pricing list --query "value[].{plan:name,tier:pricingTier}" -o table` shows `Standard` for
  servers, containers, databases and storage in use; `az security alert list --query "[?status=='Active'].{alert:alertDisplayName,severity:severity}" -o table`
  and `az security assessment list --query "[?status.code=='Unhealthy'].displayName"` have owners.

## Backup and DR

- **rule:** Every VM, database and file share is in a backup policy with recent backups (baseline: automated
  backups).
  **probe:** `az backup item list --vault-name <vault> -g <rg> --query "[].{name:properties.friendlyName,last:properties.lastBackupTime,status:properties.lastBackupStatus}" -o table`.
  Databases: `az sql db show -g <rg> -s <server> -n <db> --query earliestRestoreDate` and
  `az postgres flexible-server show -g <rg> -n <server> --query backup`.
- **rule:** Restores are tested (baseline: a backup never restored doesn't count).
  **probe:** **(pause point)** restore into a new, separately named database:
  `az sql db restore -g <rg> -s <server> -n <db> --dest-name <db>-restore-test --time <iso-time>`, or
  `az postgres flexible-server restore -g <rg> --name <server>-restore-test --source-server <server>`. Check the
  data, record the time taken, then delete the test copy (also a pause point).
- **rule:** Backups survive a compromised account: soft delete, immutability, cross-region restore (baseline:
  protected from the account).
  **probe:** `az backup vault show -g <rg> -n <vault> --query "properties.securitySettings"` and
  `az backup vault backup-properties show -g <rg> -n <vault> --query "[].properties.{storage:storageModelType,crossRegion:crossRegionRestoreFlag,softDelete:softDeleteFeatureState}"`.
- **rule:** Failover works where the design claims it (baseline: failover tested).
  **probe:** `az postgres flexible-server show -g <rg> -n <server> --query highAvailability`,
  `az sql failover-group list -g <rg> -s <server>`. **(pause point)** in non-prod:
  `az postgres flexible-server restart -g <rg> -n <server> --failover Forced` and time the recovery.

## Performance

- **rule:** Latency and errors are measured against the written target (baseline: written target).
  **probe:** with Application Insights (needs the `application-insights` extension):
  `az monitor app-insights query --app <app-insights-name> -g <rg> --analytics-query "requests | where timestamp > ago(14d) | summarize p95=percentile(duration, 95), p99=percentile(duration, 99), failed=round(100.0 * countif(success == false) / count(), 2) by bin(timestamp, 1d)"`.
  Without it, the load balancer's metric (Application Gateway `ApplicationGatewayTotalTime`, Front Door
  `TotalLatency`): `az monitor metrics list --resource <resource-id> --metric <metric> --aggregation Average Maximum --interval PT1H --offset 14d`.
- **rule:** Autoscaling keeps up (baseline: autoscaling).
  **probe:** `az monitor autoscale show -g <rg> -n <setting> --query "{min:profiles[0].capacity.minimum,max:profiles[0].capacity.maximum,rules:profiles[0].rules[].{metric:metricTrigger.metricName,op:metricTrigger.operator,threshold:metricTrigger.threshold,direction:scaleAction.direction,cooldown:scaleAction.cooldown}}"`.
- **rule:** Front Door caches what it can (baseline: caching).
  **probe:** for each route:
  `az resource show --ids /subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Cdn/profiles/<profile>/afdEndpoints/<endpoint>/routes/<route> --query "properties.cacheConfiguration"`;
  an empty result means the route caches nothing. (The afd command group needs the `front-door` extension; this uses core only.)
- **rule:** The database shows where its time goes (baseline: database).
  **probe:** Azure SQL: Query Store is on (`SELECT actual_state_desc FROM sys.database_query_store_options;` prints
  `READ_WRITE`); PostgreSQL flexible server:
  `az postgres flexible-server parameter show -g <rg> -s <server> -n pg_qs.query_capture_mode --query value` is
  `top` or `all`. Then the baseline's SQL for top queries and connections.
- **rule:** App, database and registry sit in one region (baseline: placement).
  **probe:** `az resource list -g <rg> --query "[].{name:name,type:type,location:location}" -o table`; anything on the
  request path in a different `location` is a finding unless the design needs it.
- **rule:** Functions cold starts stay off the latency-critical path (baseline: startup).
  **probe:** `az functionapp show -g <rg> -n <app> --query "{plan:appServicePlanId,alwaysOn:siteConfig.alwaysOn}"`;
  a latency-critical function on the Consumption plan has cold starts; Premium or Flex Consumption with always-ready
  instances avoids them.

## Cost

- **rule:** Required tags on everything, enforced by Azure Policy (baseline: tags enforced).
  **probe:** `az resource list --query "[?tags.owner==null].id" -o tsv` is empty;
  `az policy assignment list --query "[].displayName"` includes a require-tag policy.
- **rule:** Budgets with alerts (baseline: budgets per subscription and environment).
  **probe:** `az consumption budget list --query "[].{name:name,amount:amount,period:timeGrain}"`.
- **rule:** No idle spend (baseline: no idle resources). Azure trap: a VM that is "stopped" but not "deallocated"
  is still billed for compute.
  **probe:** stopped-not-deallocated VMs `az vm list -d --query "[?powerState=='VM stopped'].name"`; unattached
  disks `az disk list -g <rg> --query "[?diskState=='Unattached'].{name:name,sizeGb:diskSizeGb}"` (per resource group); unused public IPs
  `az network public-ip list --query "[?ipConfiguration==null && natGateway==null].{name:name,ip:ipAddress}"`;
  old snapshots `az snapshot list --query "[].{name:name,created:timeCreated}" -o table`.
- **rule:** Sized from real use (baseline: not over-provisioned).
  **probe:** Azure Advisor cost advice `az advisor recommendation list --category Cost --query "[].{impact:impact,problem:shortDescription.problem,resource:impactedValue}" -o table`;
  usage `az monitor metrics list --resource <resource-id> --metric "Percentage CPU" "Available Memory Bytes" --interval P1D --aggregation Average Maximum --offset 30d`.
- **rule:** Not running hot (baseline: not under-provisioned).
  **probe:** the same `metrics list` call with `"CPU Credits Remaining"` for B-series; App Service plan
  `CpuPercentage` and `MemoryPercentage`; autoscale limits `az monitor autoscale list -g <rg> --query "[].{name:name,max:profiles[0].capacity.maximum}"`
  compared with the current instance count.
- **rule:** Redundancy matches the target (baseline: redundancy vs availability target).
  **probe:** `az postgres flexible-server list --query "[].{name:name,ha:highAvailability.mode}"`,
  `az sql db list -g <rg> -s <server> --query "[].{name:name,zoneRedundant:zoneRedundant,sku:currentSku.name}"`,
  `az storage account list --query "[].{name:name,sku:sku.name}"` (geo-redundant `GRS`/`RAGRS` in dev is usually
  waste), matched against each environment's availability target.
- **rule:** Pricing model fits use (baseline: commitments, spot, newer generations). Azure extras: Azure Hybrid
  Benefit for Windows and SQL licenses you already own; Dev/Test subscriptions for non-prod.
  **probe:** reservation and savings-plan advice shows up in the Advisor cost list above; Windows VMs without Hybrid
  Benefit `az vm list --query "[?storageProfile.osDisk.osType=='Windows' && licenseType==null].name"`; VM sizes in use
  `az vm list --query "[].{name:name,size:hardwareProfile.vmSize}" -o table`, looking for old generations where a
  `v5`/`v6` or ARM (`Dpsv5`) size fits.
- **rule:** Storage in the right tier (baseline: lifecycle, retention, disk type).
  **probe:** `az storage account management-policy show --account-name <account> -g <rg>` returns lifecycle rules
  (an error means none); disk SKUs and provisioned IOPS
  `az disk list -g <rg> --query "[].{name:name,sku:sku.name,iops:diskIopsReadWrite}" -o table` (Premium SSD in dev is
  usually waste).
- **rule:** Data transfer is known (baseline: data transfer kept low).
  **probe:** `az consumption usage list --start-date <yyyy-mm-dd> --end-date <yyyy-mm-dd> --include-meter-details --query "[?meterDetails.meterCategory=='Bandwidth'].{cost:pretaxCost,meter:meterDetails.meterName}"`;
  private endpoints for storage and databases `az network private-endpoint list --query "[].{name:name,target:privateLinkServiceConnections[0].groupIds}"`.
- **rule:** Log spend is capped (baseline: observability spend).
  **probe:** Log Analytics retention and daily cap:
  `az monitor log-analytics workspace show -g <rg> -n <workspace> --query "{retentionDays:retentionInDays,dailyCapGb:workspaceCapping.dailyQuotaGb}"`.
- **rule:** Container Registry cleans up untagged images (baseline: registry cleanup).
  **probe:** `az acr show -n <registry> --query "{sku:sku.name,retention:policies.retentionPolicy}"`; the retention
  policy needs the Premium tier, otherwise a scheduled `acr purge` task (`az acr task list -r <registry> -o table`).
- **rule:** Licenses are counted (baseline: licenses).
  **probe:** `az vm list --query "[].{name:name,os:storageProfile.osDisk.osType,license:licenseType,size:hardwareProfile.vmSize}" -o table`;
  a Windows VM with no `licenseType` pays for the license with the VM (Azure Hybrid Benefit off).
- **rule:** Cost anomaly alerts are on (baseline: anomalies and unit cost).
  **probe:** in the portal: Cost Management, Cost alerts, anomaly alerts per subscription with a recipient.
