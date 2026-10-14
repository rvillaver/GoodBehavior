---
name: devops/aws
use-when: the project runs on AWS; install next to the baseline
---

# AWS: the baseline rules mapped to AWS services and CLI probes

Each rule points at its baseline rule (`baseline.md`) and gives the AWS way to check it. All probes are read-only
unless marked **(pause point)**: those need the user's yes first, per `devops.md`. Replace `<...>` with real values.
Every command here was checked against AWS CLI 2.36 (operation, flags, required arguments and `--query` syntax).

Before any probe, confirm which account and role you are in, and say it in the result:
`aws sts get-caller-identity`.

Cost of probing: Cost Explorer (`aws ce ...`) charges per API request. Run those sparingly.

## IaC and state

- **rule:** State bucket is versioned, encrypted and private (baseline: state is remote, encrypted, versioned).
  **probe:** `aws s3api get-bucket-versioning --bucket <state-bucket>` shows `"Status": "Enabled"`;
  `aws s3api get-bucket-encryption --bucket <state-bucket>` shows a rule; `aws s3api get-public-access-block --bucket <state-bucket>`
  shows all four settings `true`. Locking: the backend has `use_lockfile = true` (see `terraform.md`).
- **rule:** Each environment is its own AWS account, so dev credentials can't reach prod (baseline: separate state
  and credentials).
  **probe:** with the dev profile, `aws sts get-caller-identity` shows the dev account, then
  `aws s3api head-bucket --bucket <prod-state-bucket>` fails with 403 or 404.
- **rule:** No console changes outside code (baseline: everything in code).
  **probe:** `aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --max-results 50 --query 'Events[].[EventTime,Username,EventName]' --output text`
  lists recent writes; anything not made by the pipeline role needs an owner and a code change.

## CI/CD

- **rule:** The pipeline uses OIDC federation, not stored access keys (baseline: short-lived credentials).
  **probe:** `aws iam list-open-id-connect-providers` lists the CI provider;
  `aws iam get-role --role-name <ci-role> --query Role.AssumeRolePolicyDocument` shows a `sub` condition scoped to
  this repo and branch or environment; `aws iam list-access-keys --user-name <ci-user>` is empty or the user doesn't
  exist.
- **rule:** Only the protected branch can assume the prod deploy role (baseline: prod deploys gated).
  **probe:** in the prod role's trust policy (same `get-role` call), the `sub` condition names the protected branch
  or a protected environment, never a wildcard like `repo:<org>/<repo>:*`.

## Secrets and identity

- **rule:** Secrets live in Secrets Manager or SSM Parameter Store (SecureString), and rotate (baseline: secret
  manager, rotation).
  **probe:** `aws secretsmanager list-secrets --query 'SecretList[].[Name,RotationEnabled,LastRotatedDate]' --output table`;
  each secret has rotation on or a written reason. **(pause point)** test rotation in non-prod:
  `aws secretsmanager rotate-secret --secret-id <secret>`, then check the app still works.
- **rule:** Workloads use IAM roles (instance profile, task role, IRSA/Pod Identity), not access keys (baseline:
  workload identity).
  **probe:** from inside the workload, `aws sts get-caller-identity` returns an `assumed-role/<expected-role>` ARN,
  not a `user/` ARN.
- **rule:** Least privilege (baseline: each identity can do its job and nothing more).
  **probe:** without touching anything, ask IAM what a role may do:
  `aws iam simulate-principal-policy --policy-source-arn <role-arn> --action-names s3:GetObject s3:DeleteObject --resource-arns arn:aws:s3:::<other-bucket>/*`
  shows `implicitDeny` or `explicitDeny` for actions it must not have. Access Analyzer:
  `aws accessanalyzer list-analyzers` exists and `aws accessanalyzer list-findings --analyzer-arn <arn>` is reviewed.
- **rule:** Root has no access keys and has MFA; humans use IAM Identity Center (baseline: SSO, MFA, root locked).
  **probe:** `aws iam get-account-summary --query 'SummaryMap.[AccountAccessKeysPresent,AccountMFAEnabled]'` shows
  `[0, 1]`. `aws iam list-users --query 'Users[].UserName'` is empty or each user has a reason.

## Networking

- **rule:** No world-open admin or database ports (baseline: ingress limited).
  **probe:** `aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[].[GroupId,GroupName]' --output text`;
  for each, `aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg-id>` shows only 80/443 open to
  `0.0.0.0/0`.
- **rule:** Databases and buckets are not public (baseline: nothing public unless meant to be).
  **probe:** `aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible].DBInstanceIdentifier'` is
  empty; `aws s3control get-public-access-block --account-id <account-id>` shows all four settings `true`.
- **rule:** Certificates are managed by ACM and renew on their own (baseline: TLS renewed automatically).
  **probe:** `aws acm list-certificates --query 'CertificateSummaryList[].[DomainName,Status,RenewalEligibility,NotAfter]' --output table`;
  all `ISSUED` and `ELIGIBLE`. Then `openssl s_client` from outside, per baseline.
- **rule:** DNS in Route 53 matches what resolves (baseline: DNS in code, resolves as intended).
  **probe:** `aws route53 list-resource-record-sets --hosted-zone-id <zone-id> --query 'ResourceRecordSets[].[Name,Type]' --output text`,
  compared with `dig +short <name>` from outside and from inside the VPC.
- **rule:** Egress goes through known NAT addresses (baseline: known outbound path).
  **probe:** `aws ec2 describe-nat-gateways --query 'NatGateways[].NatGatewayAddresses[].PublicIp'` matches what
  `curl -s https://checkip.amazonaws.com` returns from the workload.

## Observability

- **rule:** CloudTrail is on in all regions and can't be deleted by workloads (baseline: audit log on and
  protected).
  **probe:** `aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,S3BucketName]'` shows a
  multi-region trail; `aws cloudtrail get-trail-status --name <trail> --query IsLogging` is `true`. Check the workload
  role can't stop it: `aws iam simulate-principal-policy --policy-source-arn <role-arn> --action-names cloudtrail:StopLogging cloudtrail:DeleteTrail`
  shows denies.
- **rule:** Every log group has a retention (baseline: central logs with a set retention).
  **probe:** `aws logs describe-log-groups --query 'logGroups[?!retentionInDays].logGroupName'` is empty.
- **rule:** Alarms exist and send to a human (baseline: alerts reach a human).
  **probe:** `aws cloudwatch describe-alarms --query 'MetricAlarms[?!AlarmActions].AlarmName'` is empty (every alarm
  has an action). **(pause point)** test one:
  `aws cloudwatch set-alarm-state --alarm-name <alarm> --state-value ALARM --state-reason test` and confirm the
  page or message arrives.
- **rule:** Public endpoints have an outside health check (baseline: uptime probe from outside).
  **probe:** `aws route53 list-health-checks --query 'HealthChecks[].HealthCheckConfig.[FullyQualifiedDomainName,Type]'`
  or `aws synthetics describe-canaries --query 'Canaries[].[Name,Status.State]'`.

## Security and attack surface

- **rule:** Public apps sit behind AWS WAF with managed rules: core rule set, SQL injection, known bad inputs, bot
  control on login and signup, and a rate-based rule (baseline: WAF, injection, bots, rate limits).
  **probe:** `aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].[Name,Id,ARN]' --output text` (and
  `--scope CLOUDFRONT --region us-east-1` for CloudFront); for each,
  `aws wafv2 get-web-acl --name <acl-name> --scope REGIONAL --id <acl-id> --query 'WebACL.Rules[].Name'` lists
  `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, a
  rate-based rule, and `AWSManagedRulesBotControlRuleSet` where bots matter;
  `aws wafv2 list-resources-for-web-acl --web-acl-arn <acl-arn>` shows every public load balancer or API attached.
- **rule:** Nothing public bypasses the WAF (baseline: origin locked).
  **probe:** internet-facing load balancers `aws elbv2 describe-load-balancers --query "LoadBalancers[?Scheme=='internet-facing'].[LoadBalancerName,DNSName]" --output text`;
  each is in a web ACL above, or only accepts CloudFront (security group allows the
  `com.amazonaws.global.cloudfront.origin-facing` prefix list only).
- **rule:** DDoS protection fits the risk: Shield Standard is automatic; Shield Advanced for business-critical public
  apps (baseline: DDoS limits).
  **probe:** `aws shield describe-subscription` (an error means Standard only) and
  `aws shield list-protections --query 'Protections[].[Name,ResourceArn]'`.
- **rule:** TLS 1.2+ on every listener and distribution (baseline: TLS).
  **probe:** `aws elbv2 describe-listeners --load-balancer-arn <lb-arn> --query 'Listeners[].[Port,Protocol,SslPolicy]'`
  shows a TLS 1.2+ policy (for example `ELBSecurityPolicy-TLS13-1-2-2021-06`);
  `aws cloudfront list-distributions --query 'DistributionList.Items[].[Id,WebACLId,ViewerCertificate.MinimumProtocolVersion]'`
  shows a web ACL and `TLSv1.2_2021`.
- **rule:** Admin access through Session Manager, not open SSH or RDP (baseline: admin access never public).
  **probe:** `aws ssm describe-instance-information --query 'InstanceInformationList[].[InstanceId,PingStatus]'`
  lists the instances; the security-group probe in Networking shows no 22 or 3389 open to the world.
- **rule:** Threat detection is on and read (baseline: detection).
  **probe:** `aws guardduty list-detectors` returns a detector;
  `aws guardduty list-findings --detector-id <detector-id> --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'`
  has none unreviewed; `aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' --max-items 20`.
- **rule:** Instances require IMDSv2, so a server-side request forgery bug in an app can't steal the instance's role
  credentials (baseline: workload identity).
  **probe:** `aws ec2 describe-instances --query "Reservations[].Instances[?MetadataOptions.HttpTokens!='required'].[InstanceId,MetadataOptions.HttpTokens]" --output text`
  prints nothing.
- **rule:** New disks are encrypted by default (baseline: nothing stored in the clear).
  **probe:** `aws ec2 get-ebs-encryption-by-default` shows `true` in every region in use;
  `aws ec2 describe-volumes --filters Name=encrypted,Values=false --query 'Volumes[].VolumeId' --output text` prints
  nothing.
- **rule:** The whole account is scanned against a standard, not only the services this guide names (baseline:
  know the whole attack surface).
  **probe:** Prowler (open source, read-only API calls; tested with 5.44):
  `prowler aws --profile <profile> --region <region> --severity critical high --output-formats csv html`, and for card
  data add `--compliance pci_4.0_aws`. If Security Hub is on, `aws securityhub get-enabled-standards` lists the CIS or
  Foundational Best Practices standard. Every FAIL is a finding or has a written reason.
- **rule:** Vulnerabilities in instances, images and functions are found (baseline: vulnerability scanning).
  **probe:** `aws inspector2 list-findings --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' --max-results 20`
  and `aws ecr describe-image-scan-findings --repository-name <repo> --image-id imageTag=<tag> --query 'imageScanFindings.findingSeverityCounts'`.

## Backup and DR

- **rule:** AWS Backup plans cover every stateful store (baseline: automated backups).
  **probe:** `aws backup list-protected-resources --query 'Results[].[ResourceArn,LastBackupTime]' --output table`
  lists each database, volume and file system with a recent backup. For RDS:
  `aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,BackupRetentionPeriod,LatestRestorableTime]'`.
- **rule:** Restores are tested (baseline: a backup never restored doesn't count).
  **probe:** `aws backup list-restore-testing-plans` shows a restore-testing plan, or **(pause point)** restore into a
  new, separately named instance:
  `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier <db> --target-db-instance-identifier <db>-restore-test --use-latest-restorable-time`,
  check the data, record the time taken, then delete the test instance (also a pause point).
- **rule:** Backups are locked and copied out of the account that made them (baseline: protected from the account).
  **probe:** `aws backup describe-backup-vault --backup-vault-name <vault> --query '[Locked,MinRetentionDays]'` shows
  `true`; `aws backup get-backup-plan --backup-plan-id <plan-id> --query 'BackupPlan.Rules[].CopyActions'` copies to
  another account or region.
- **rule:** Multi-AZ failover works where the design claims it (baseline: failover tested).
  **probe:** `aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,MultiAZ]'`.
  **(pause point)** in non-prod: `aws rds reboot-db-instance --db-instance-identifier <db> --force-failover` and time
  the recovery.

## Cost

- **rule:** Required tags on everything (baseline: tags enforced).
  **probe:** `aws resourcegroupstaggingapi get-resources --query "ResourceTagMappingList[?!(Tags[?Key=='owner'])].ResourceARN"`
  is empty. Enforce with Organizations tag policies and SCPs.
- **rule:** Budgets with alerts (baseline: budgets per account and environment).
  **probe:** `aws budgets describe-budgets --account-id <account-id> --query 'Budgets[].[BudgetName,BudgetLimit.Amount]'`
  and `aws budgets describe-notifications-for-budget --account-id <account-id> --budget-name <budget>`.
- **rule:** No idle spend (baseline: no idle resources).
  **probe:** unattached volumes `aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[].[VolumeId,Size]'`;
  unused Elastic IPs `aws ec2 describe-addresses --query 'Addresses[?!AssociationId].PublicIp'`; stopped instances
  still paying for disks `aws ec2 describe-instances --filters Name=instance-state-name,Values=stopped --query 'Reservations[].Instances[].InstanceId'`;
  old snapshots `aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].[SnapshotId,StartTime]' --output text`.
- **rule:** Sized from real use (baseline: not over-provisioned).
  **probe:** `aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --dimensions Name=InstanceId,Value=<instance-id> --start-time <30-days-ago> --end-time <now> --period 86400 --statistics Average Maximum`.
  Memory needs the CloudWatch agent (namespace `CWAgent`). Compute Optimizer, once opted in:
  `aws compute-optimizer get-ec2-instance-recommendations`.
- **rule:** Not running hot (baseline: not under-provisioned).
  **probe:** burst credits `CPUCreditBalance` (T instances), RDS `FreeableMemory` and `CPUUtilization`, EBS
  `VolumeQueueLength`, via the same `get-metric-statistics` call; autoscaling groups pinned at max:
  `aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[?DesiredCapacity==MaxSize].AutoScalingGroupName'`.
- **rule:** Redundancy matches the target (baseline: redundancy vs availability target).
  **probe:** Multi-AZ databases `aws rds describe-db-instances --query 'DBInstances[?MultiAZ].DBInstanceIdentifier'`,
  NAT gateways per VPC `aws ec2 describe-nat-gateways --query 'NatGateways[].[VpcId,SubnetId]' --output text`, load
  balancers with no healthy targets `aws elbv2 describe-target-health --target-group-arn <tg-arn>`, matched against
  each environment's availability target.
- **rule:** Pricing model fits use (baseline: commitments, spot, newer generations).
  **probe:** Savings Plans coverage `aws ce get-savings-plans-coverage --time-period Start=<yyyy-mm-dd>,End=<yyyy-mm-dd>`
  and reservation use `aws ce get-reservation-utilization --time-period Start=<yyyy-mm-dd>,End=<yyyy-mm-dd>`; instance
  types in use `aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceType' --output text`, looking
  for old generations (for example `m4`, `m5`) where Graviton (`m7g`) or a newer type fits.
- **rule:** Storage in the right tier (baseline: lifecycle, retention, disk type).
  **probe:** `aws s3api get-bucket-lifecycle-configuration --bucket <bucket>` returns rules (an error
  `NoSuchLifecycleConfiguration` means none); `gp2` and `io1` volumes that should be `gp3`:
  `aws ec2 describe-volumes --filters Name=volume-type,Values=gp2,io1 --query 'Volumes[].[VolumeId,VolumeType,Iops]'`.
- **rule:** Data transfer is known (baseline: data transfer kept low).
  **probe:** `aws ce get-cost-and-usage --time-period Start=<yyyy-mm-dd>,End=<yyyy-mm-dd> --granularity MONTHLY --metrics UnblendedCost --group-by Type=DIMENSION,Key=USAGE_TYPE`,
  looking at `DataTransfer` and `NatGateway-Bytes`. S3 and DynamoDB gateway endpoints exist (they're free):
  `aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].[VpcId,ServiceName,VpcEndpointType]'`.
