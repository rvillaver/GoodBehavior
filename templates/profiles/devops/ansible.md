---
name: devops/ansible
use-when: the project configures hosts with Ansible (playbooks, roles, inventories); install next to the baseline
---

# Ansible: rules for safe, repeatable playbooks, each with its probe

Probes marked "tested" were run in October 2026 with ansible-lint 25.6 (installed in a throwaway Python container)
on a sample playbook. Linting and `--check` runs only read; a real playbook run changes hosts and is a **(pause
point)**, per `devops.md`.

## Before running a playbook

- **rule:** Preview every run: `--check --diff` against the same inventory and limit first, and read what it would
  change. Check mode skips `command` and `shell` tasks unless they set `check_mode: false`, so the preview can miss
  what they do.
  **probe:** `ansible-playbook -i <inventory> <playbook> --check --diff --limit <hosts>` shows only the expected
  changes. **(pause point)** the real run, after the user's yes.
- **rule:** Each environment has its own inventory, and prod runs roll out in batches (`serial`) with a failure
  limit, so a bad change stops after the first hosts.
  **probe:** `ls inventories/` (or the project's layout) has one inventory per environment; plays that touch prod
  hosts set `serial:` and `max_fail_percentage:` (`grep -rnE 'serial:|max_fail_percentage:' <playbook-dir>`).

## Code

- **rule:** Playbooks pass ansible-lint with the `production` profile.
  **probe:** `ansible-lint --profile production` prints no violations (tested: it flagged `shell` with no
  `changed_when`, short module names, unnamed tasks and unset file permissions). Without it installed, run it in a
  container: `docker run --rm -v "$PWD":/src -w /src python:3.13-slim sh -c 'pip install -q ansible-lint && ansible-lint --profile production'`.
- **rule:** Running a playbook twice changes nothing the second time: use modules, not `shell` or `command`; when a
  command is needed, give it `creates:`, `removes:` or `changed_when:`.
  **probe:** `grep -rnE '^[[:space:]]*(ansible\.builtin\.)?(shell|command|raw):' <playbook-dir>`; each hit has
  `changed_when`, `creates` or `removes` (ansible-lint `no-changed-when`). **(pause point)** in non-prod, run the
  playbook twice; the second recap shows `changed=0`.
- **rule:** Secrets come from Ansible Vault or a secret-manager lookup, never plain in `group_vars`, and tasks that
  handle them set `no_log: true` so values don't land in logs. ansible-lint does not catch a missing `no_log`
  (tested).
  **probe:** plain secret values: the on-prem guide's `group_vars`/`host_vars` grep. Tasks using secret variables:
  `grep -rnE '\{\{[^}]*(password|secret|token|key)[^}]*\}\}' <playbook-dir>`; each task listed has `no_log: true`.
- **rule:** Module names are fully qualified (`ansible.builtin.copy`), and collections and roles are pinned in
  `requirements.yml`.
  **probe:** ansible-lint `fqcn` doesn't appear (tested); every entry in `collections/requirements.yml` and
  `roles/requirements.yml` has a `version:`.
- **rule:** Files and templates set an owner, group and mode; secret files are `0600` or `0640`.
  **probe:** ansible-lint `risky-file-permissions` doesn't appear (tested).
