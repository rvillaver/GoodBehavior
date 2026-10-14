---
name: devops/digitalocean
use-when: the project runs on DigitalOcean; install next to the baseline
---

# DigitalOcean: the baseline rules mapped to DigitalOcean services and CLI probes

Each rule points at its baseline rule (`baseline.md`) and gives the DigitalOcean way to check it. All probes are
read-only unless marked **(pause point)**: those need the user's yes first, per `devops.md`. Replace `<...>` with
real values. Every `doctl` command here was checked against doctl 1.166 (command and flags; doctl checks for a
token before it checks positional arguments, so those were reviewed by eye). Spaces is S3-compatible, so bucket
probes use the AWS CLI with `--endpoint-url https://<region>.digitaloceanspaces.com`; those were checked against
AWS CLI 2.36.

DigitalOcean has fewer built-in controls than the big three: no OIDC federation for the API, no managed secret
store, no account-wide audit log API. Where a rule needs one of those, the guide says what to use instead.

Before any probe, confirm which team and token context you are using, and say it in the result:
`doctl account get` and `doctl auth list`.

## IaC and state

- **rule:** State lives in a private, versioned Spaces bucket (baseline: state is remote, encrypted, versioned).
  **probe:** `aws s3api get-bucket-versioning --bucket <state-bucket> --endpoint-url https://<region>.digitaloceanspaces.com`
  shows `"Status": "Enabled"`, using Spaces keys. **Locking:** run the lock probe from `terraform.md` against this
  backend before trusting it. If a second run is not blocked, keep state in a backend that locks (for example HCP
  Terraform) instead.
- **rule:** Each environment is a separate team, or at least a separate project with its own scoped API token, so a
  dev token can't touch prod (baseline: separate state and credentials).
  **probe:** `doctl projects list` shows one project per environment. With the dev token, a read of a prod
  resource (`doctl compute droplet get <prod-droplet-id>`) fails.
- **rule:** No control-panel changes outside code (baseline: everything in code). DigitalOcean has no audit-log
  API for resources.
  **probe:** run `terraform plan -detailed-exitcode` (exit 0 = no drift), and review the team's security history in
  the control panel.

## CI/CD

- **rule:** The pipeline uses a scoped API token with an expiry, stored as a CI secret and rotated, because the
  DigitalOcean API has no OIDC federation (baseline: short-lived credentials).
  **probe:** in the control panel's API tokens page, the CI token has only the scopes it needs and an expiry date.
  List the CI secrets: no full-access tokens.
- **rule:** Prod deploys run only from the protected branch, with an approval (baseline: prod deploys gated).
  **probe:** the prod token is stored only in the protected environment's secrets in CI.

## Secrets and identity

- **rule:** App secrets are App Platform `SECRET` variables or an external secret manager, never plain values in
  the app spec or repo (baseline: secret manager).
  **probe:** `doctl apps spec get <app-id>` shows every sensitive variable with `type: SECRET` and no plain value.
- **rule:** Team members use 2FA and the least role they need (baseline: SSO, MFA, least privilege).
  **probe:** in the control panel's team settings, 2FA is required and owners are few and named.

## Networking

- **rule:** Every droplet sits behind a Cloud Firewall with no world-open admin or database ports (baseline:
  ingress limited).
  **probe:** `doctl compute firewall list --format ID,Name,InboundRules,DropletIDs,Tags` shows only 80/443 open to
  `0.0.0.0/0`; `doctl compute droplet list --format ID,Name,Tags` compared with the firewall's droplets and tags
  finds no droplet left out.
- **rule:** Managed databases accept connections only from trusted sources (baseline: nothing public unless meant
  to be). DigitalOcean trap: a database with no trusted sources accepts connections from anywhere.
  **probe:** `doctl databases firewalls list <database-id>` is not empty, and lists only the app's droplets, tags,
  VPC or apps.
- **rule:** Load balancer certificates renew on their own (baseline: TLS renewed automatically).
  **probe:** `doctl compute certificate list --format Name,Type,State,NotAfter` shows `lets_encrypt` type
  certificates. Then `openssl s_client` from outside.
- **rule:** DNS records match what resolves (baseline: DNS in code, resolves as intended).
  **probe:** `doctl compute domain records list <domain> --format Type,Name,Data`, compared with `dig +short <name>`.
- **rule:** Outbound addresses are known (baseline: known outbound path).
  **probe:** `doctl compute reserved-ip list --format IP,DropletID` and `doctl compute droplet list --format Name,PublicIPv4`
  match `curl -s https://ifconfig.me` from the workload.

## Observability

- **rule:** Logs leave the droplet and are kept (baseline: central logs with a set retention). DigitalOcean has no
  central log service for droplets.
  **probe:** App Platform: `doctl apps spec get <app-id>` shows a `log_destinations` entry. Droplets: a log shipper
  is installed and its destination shows a recent test event.
- **rule:** Alerts exist and reach a human (baseline: alerts reach a human).
  **probe:** `doctl monitoring alert list --format UUID,Type,Description,Enabled,Emails,SlackChannels`; every alert
  has an email or Slack target. Droplet metrics need the monitoring agent. **(pause point)** to test, cross a
  threshold on a non-prod droplet and confirm the alert arrives.
- **rule:** Public endpoints have an uptime check (baseline: uptime probe from outside).
  **probe:** `doctl monitoring uptime list`.

## Security and attack surface

DigitalOcean has network-level DDoS protection but no WAF, bot management or rate limiting of its own. Put a CDN or
WAF in front of public apps (for example Cloudflare), and check those defenses there.

- **rule:** Public apps sit behind an external WAF/CDN with managed rules, rate limits and bot protection, and the
  origin only accepts traffic from it (baseline: WAF, injection, bots, rate limits, origin locked).
  **probe:** in the WAF/CDN, the managed rule set, rate-limit and bot rules are on; on DigitalOcean, the Cloud
  Firewall inbound rules for web ports allow only the CDN's published address ranges
  (`doctl compute firewall get <firewall-id> --format Name,InboundRules`).
- **rule:** Load balancers redirect HTTP to HTTPS and use managed certificates (baseline: TLS).
  **probe:** `doctl compute load-balancer get <lb-id> --format Name,RedirectHttpToHttps,ForwardingRules`.
- **rule:** Admin access over a VPN or the droplet console, not SSH open to the world; SSH keys only (baseline:
  admin access never public).
  **probe:** the firewall probe in Networking shows no 22 from `0.0.0.0/0`; on the droplet, `sshd -T` shows
  `passwordauthentication no` (see `onprem.md`).
- **rule:** Images and droplets are scanned for vulnerabilities, since DigitalOcean doesn't do it for you
  (baseline: vulnerability scanning).
  **probe:** `trivy image --severity HIGH,CRITICAL <image>` for each image; on droplets, the patch probes in
  `onprem.md`.

## Backup and DR

- **rule:** Droplets with data have backups on; managed databases have daily backups (baseline: automated
  backups).
  **probe:** `doctl compute droplet list --format Name,Features` shows `backups` for droplets that hold data;
  `doctl compute droplet backups <droplet-id>` lists recent ones; `doctl databases backups <database-id>`.
- **rule:** Restores are tested (baseline: a backup never restored doesn't count).
  **probe:** **(pause point)** fork the database into a new cluster:
  `doctl databases fork <database-id>-restore-test --restore-from-cluster-id <database-id>`, check the data, record
  the time taken, then delete the fork (also a pause point).
- **rule:** A copy lives outside this team, because DigitalOcean backups stay in the same account (baseline:
  protected from the account).
  **probe:** an export job (for example a nightly `pg_dump` to storage in another account or provider) exists, and
  its newest copy is inside the expected window.
- **rule:** Database standby nodes exist where the design claims high availability (baseline: failover tested).
  **probe:** `doctl databases list --format Name,Engine,Size,NumNodes,Region`; more than one node where HA is
  claimed.

## Cost

- **rule:** Resources carry tags and sit in the right project (baseline: tags enforced).
  **probe:** `doctl compute droplet list --format Name,Tags` and `doctl projects resources list <project-id>`; every
  resource has an owner tag and belongs to a project.
- **rule:** Billing alerts are on (baseline: budgets with alerts).
  **probe:** the billing alert threshold is set in the control panel; `doctl balance get` shows month-to-date usage.
- **rule:** No idle spend (baseline: no idle resources). DigitalOcean trap: a powered-off droplet is still billed
  in full; only destroying it stops the charge.
  **probe:** powered-off droplets `doctl compute droplet list --format Name,Status,Size`; unattached volumes
  `doctl compute volume list --format Name,Size,DropletIDs`; unassigned reserved IPs
  `doctl compute reserved-ip list --format IP,DropletID`; old snapshots `doctl compute snapshot list --format Name,Size,CreatedAt`.
- **rule:** Sized from real use (baseline: not over-provisioned, not under-provisioned).
  **probe:** droplet CPU, memory and disk graphs (monitoring agent needed) over 14+ days in the control panel,
  compared with the size; `doctl compute size list` for the next size down or up.
- **rule:** Redundancy matches the target (baseline: redundancy vs availability target).
  **probe:** `doctl databases list --format Name,Size,NumNodes` (standby nodes in dev are usually waste) and
  `doctl compute load-balancer list --format Name,Status,DropletIDs` (a load balancer with no droplets is waste),
  matched against each environment's availability target.
- **rule:** The droplet type fits the load (baseline: pricing model). DigitalOcean has no reservations or spot: the
  levers are size, type (Basic, General Purpose, CPU-Optimized) and App Platform vs droplets.
  **probe:** `doctl compute droplet list --format Name,Size` compared with the usage graphs.
- **rule:** Storage in the right place (baseline: lifecycle, retention).
  **probe:** `aws s3api get-bucket-lifecycle-configuration --bucket <bucket> --endpoint-url https://<region>.digitaloceanspaces.com`
  returns rules; volumes sized to need (`doctl compute volume list --format Name,Size`).
- **rule:** Bandwidth stays inside the pooled allowance (baseline: data transfer kept low).
  **probe:** `doctl invoice list` then `doctl invoice summary <invoice-uuid>`, looking for bandwidth overage; keep
  droplet-to-database traffic on the VPC (private) network.
