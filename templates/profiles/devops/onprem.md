---
name: devops/onprem
use-when: the project runs on its own servers or private cloud (bare metal, VMware, Proxmox, Hyper-V); install next to the baseline
---

# On-prem: the baseline rules mapped to Linux servers and standard tools

Each rule points at its baseline rule (`baseline.md`) and gives the on-prem way to check it, with standard Linux
tools. Hypervisor steps name the tool for the common platforms. All probes are read-only unless marked
**(pause point)**: those need the user's yes first, per `devops.md`. Replace `<...>` with real values. Many probes
need `sudo`: say so when you ask.

On-prem has no provider API to read state back from, so the host itself is the truth source. Before any probe, say
which host and environment you are on: `hostname -f` and the inventory group it belongs to.

## IaC and state

- **rule:** Server config is in code (Ansible or similar) and the hosts match it (baseline: everything in code).
  **probe:** `ansible-playbook -i <inventory> site.yml --check --diff` reports no changes. Changes mean drift or a
  hand edit on the host.
- **rule:** Terraform for VMs (vSphere, Proxmox, Hyper-V providers) keeps state in a backend that locks: PostgreSQL
  (`pg`), Consul, or an S3-compatible store such as MinIO (baseline: state remote, locked).
  **probe:** run the lock probe from `terraform.md` against that backend.
- **rule:** Each environment has its own inventory, credentials and vault password (baseline: separate state and
  credentials).
  **probe:** `ansible-inventory -i <dev-inventory> --list` contains no prod hosts; the dev vault password can't
  decrypt prod vault files.
- **rule:** Hand changes on servers are visible (baseline: no changes outside code).
  **probe:** `journalctl _COMM=sudo --since "7 days ago"` lists sudo commands run by hand; each needs an owner and a
  code change.

## CI/CD

- **rule:** Deploys run from a CI runner with short-lived SSH certificates (an SSH CA such as Vault or step-ca), not
  long-lived keys copied around (baseline: short-lived credentials).
  **probe:** `ssh-keygen -L -f <deploy-cert.pub>` shows a short "Valid" window; `authorized_keys` on the hosts holds
  no personal or stale keys.
- **rule:** Only the protected branch can deploy to prod (baseline: prod deploys gated).
  **probe:** the prod SSH certificate or vault password is available only to the protected environment in CI.

## Secrets and identity

- **rule:** Secrets are in Ansible Vault or HashiCorp Vault, never plain text in the repo or on disk in readable
  files (baseline: secret manager).
  **probe:** `grep -rnE '(password|secret|token)\s*[:=]' <repo>` finds only vaulted values; config files with
  secrets are mode `600` and owned by the service user (`stat -c '%a %U' <file>`).
- **rule:** Central accounts (LDAP, FreeIPA or SSO), no shared logins, no root over SSH, no SSH passwords
  (baseline: SSO, MFA, root locked).
  **probe:** `sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication)'` shows
  `permitrootlogin no`, `passwordauthentication no`, `pubkeyauthentication yes`. Stock Debian 12 shows
  `permitrootlogin without-password` and `passwordauthentication yes`, so a fresh server fails this until hardened.
- **rule:** Least privilege for service and deploy users (baseline: each identity can do its job and nothing more).
  **probe:** `sudo -l -U <service-user>` lists only the commands it needs, never `(ALL) ALL`.

## Networking

- **rule:** Only expected ports listen, and databases are reachable only from their app hosts (baseline: nothing
  exposed unless meant to be).
  **probe:** `sudo ss -tlnp` on the host lists the expected services; from another network segment,
  `nc -zv -w 3 <host> <port>` is refused or times out for database and admin ports, and connects from the app host.
- **rule:** A host firewall is on (baseline: ingress limited).
  **probe:** `sudo nft list ruleset`, `sudo iptables -S` or `sudo ufw status verbose` shows a default-deny inbound
  policy with named exceptions.
- **rule:** Certificates renew on their own (baseline: TLS renewed automatically).
  **probe:** `openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null | openssl x509 -noout -enddate`
  is more than 14 days out; `sudo certbot certificates` and `systemctl list-timers` show the renewal timer.
- **rule:** Internal DNS answers as intended (baseline: DNS resolves as intended).
  **probe:** `dig +short @<internal-dns-server> <name>` from inside, and `dig +short <name>` from outside for public
  names.
- **rule:** Clocks are in sync; drift breaks TLS, Kerberos and log timelines.
  **probe:** `timedatectl show -p NTPSynchronized --value` prints `yes`, or `chronyc tracking` shows a small offset.

## Observability

- **rule:** Logs are shipped to a central server and kept (baseline: central logs with a set retention).
  **probe:** `logger -t goodbehavior-probe "probe-<random>"` on the host, then find that line on the central log
  server within minutes. (It writes one harmless log line.)
- **rule:** Metrics and alerts exist and reach a human (baseline: alerts reach a human).
  **probe:** `curl -s http://<host>:9100/metrics | head` (node exporter) answers; the alert rules include disk,
  memory, CPU, service down and certificate expiry. **(pause point)** to test, fire a test alert through
  Alertmanager and confirm it arrives.
- **rule:** Hardware health is watched: disks, RAID, power (on-prem only).
  **probe:** `sudo smartctl -H /dev/<disk>` reports `PASSED`; `cat /proc/mdstat` (software RAID) shows no failed
  members (`[UU]`); `df -h` and `df -i` show headroom on every filesystem.

## Security and attack surface

- **rule:** Public web apps sit behind a WAF (an external CDN/WAF, or ModSecurity with the OWASP Core Rule Set on the
  reverse proxy) with rate limits on login and API paths (baseline: WAF, injection, rate limits).
  **probe:** the reverse proxy config loads the rule set and limits (`sudo nginx -T | grep -iE 'modsecurity|limit_req'`
  or the Apache equivalent), and `sudo nginx -t` passes.
- **rule:** Brute force and abusive clients are banned automatically (baseline: bots, detection).
  **probe:** `sudo fail2ban-client status` lists jails for SSH and the web app, or `sudo cscli decisions list`
  (CrowdSec) shows active bans.
- **rule:** Servers are patched, and security updates install on their own (baseline: vulnerability scanning).
  **probe:** `apt list --upgradable 2>/dev/null | grep -i security` is empty or recent;
  `systemctl is-enabled unattended-upgrades` is `enabled`; `sudo needrestart -b` shows no pending kernel or service
  restarts. A read-only hardening scan: `sudo lynis audit system --quick`.
- **rule:** Only expected ports are reachable from the internet (baseline: attack surface).
  **probe:** **(pause point)** from outside your network, `nmap -Pn --top-ports 100 <public-ip>` shows only the
  ports you publish.

## Backup and DR

- **rule:** Follow 3-2-1: three copies, two kinds of media, one off-site (baseline: automated backups).
  **probe:** `restic snapshots --latest 1` or `borg list --last 1 <repo>` shows a recent backup for each host and
  database; `restic check` passes.
- **rule:** Restores are tested (baseline: a backup never restored doesn't count).
  **probe:** **(pause point)** restore into a scratch folder or a scratch host, never over the source:
  `restic restore latest --target /tmp/restore-test`, then compare with `diff -r` or load the database dump into a
  scratch instance and run a known query. Record the time taken.
- **rule:** The off-site copy can't be deleted from the production hosts (baseline: protected from the account).
  **probe:** the backup repository is append-only (for example rest-server with `--append-only`) or object-locked;
  from a production host, try to delete an old snapshot: **(pause point)** it must fail.
- **rule:** Hypervisor HA and power redundancy work where the design claims them (baseline: failover tested).
  **probe:** Proxmox `ha-manager status`; VMware HA in vCenter; UPS status via `upsc <ups>` (NUT).
  **(pause point)** in a maintenance window, migrate or fail a host and time the recovery.

## Cost

On-prem cost is hardware, power, space, support contracts and licenses. The same rules apply: don't pay for
capacity nobody uses, and don't starve what is busy.

- **rule:** Every VM has an owner and a purpose (baseline: tags).
  **probe:** the hypervisor's VM list has an owner and environment in notes or tags; VMs with no owner go on a
  review list.
- **rule:** VMs are sized from real use (baseline: not over-provisioned).
  **probe:** 14+ days of history from the monitoring system, or `sar -u` and `sar -r` from sysstat (history exists
  only if sysstat collection is enabled, e.g. `ENABLED="true"` in `/etc/default/sysstat` on Debian), compared with
  allocated vCPU and memory. Over-sized VMs waste host capacity and licenses that are often priced per core.
- **rule:** Nothing runs hot (baseline: not under-provisioned).
  **probe:** load average above the core count (`uptime`, `nproc`), swap in use (`free -m`, `vmstat 5 3`),
  out-of-memory kills (`journalctl -k | grep -i 'out of memory'`), and high CPU ready time on the hypervisor.
- **rule:** No idle VMs or snapshot sprawl (baseline: no idle resources).
  **probe:** VMs powered on with no traffic or logins for 30 days; old hypervisor snapshots (Proxmox
  `qm listsnapshot <vmid>`, vSphere `govc snapshot.tree -vm <vm>`). Old VM snapshots also slow the VM down.
- **rule:** Redundancy matches the target (baseline: redundancy vs availability target).
  **probe:** RAID level, dual power supplies, clustered services and replicas per environment, matched against
  each environment's availability target. Dev rarely needs a cluster.
- **rule:** Storage is not wasted (baseline: storage tier and retention).
  **probe:** thin-provisioned disks where possible, log rotation on (`/etc/logrotate.d/`), backup retention matched
  to the written RPO, and `du -sh /var/log /var/lib/docker` on the biggest hosts.
