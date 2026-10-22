---
name: devops/terraform
use-when: the project uses Terraform or OpenTofu; install next to the baseline and the provider guides
---

# Terraform: rules for a safe apply, each with its probe

Every probe below was run against Terraform 1.15 (the rules added in October 2026 against 1.16.5, on a local
project with no cloud provider). Probes are read-only unless marked **(pause point)**: those need the
user's yes first, per `devops.md`.

## The apply itself

- **rule:** Never apply without a saved plan. Run `terraform plan -out=tfplan`, review it, then apply **that file**
  (`terraform apply tfplan`). Never `apply -auto-approve` on a fresh plan. A "tiny change" can replace a database.
  **probe:** list every delete and replace in the saved plan, and name each one to the user before asking:
  `terraform show -json tfplan | jq -r '.resource_changes[] | select(.change.actions | index("delete")) | "\(.change.actions | join("+"))  \(.address)"'`.
  `delete+create` or `create+delete` means replace: the old resource and its data are gone.
- **rule:** After the apply, the code and the real infrastructure match.
  **probe:** `terraform plan -detailed-exitcode` exits `0` (no changes). Exit `2` means drift, a console change, or
  a value that changes on every run.
- **rule:** Stateful resources (databases, disks, buckets, keys) are protected from accidental deletion.
  **probe:** grep each one for `lifecycle { prevent_destroy = true }`. It makes a plan
  that would delete the resource fail instead of running.
- **rule:** In CI, plan and apply are separate steps with a human approval between them, and the apply uses the
  plan artifact from the plan step.
  **probe:** read the pipeline: a `plan -out` step, an approval gate, then `apply <planfile>`. No `-auto-approve`
  without a plan file, no `-lock=false`.

## State

- **rule:** State is remote, encrypted, versioned and access-restricted. Never on a laptop, never in git.
  **probe:** `git ls-files | grep -E '\.tfstate'` prints nothing; `.gitignore` covers `*.tfstate*`. Read the
  `backend` block. Check versioning and access on the state bucket with the provider guide's probe.
- **rule:** State is locked so two runs can't change it at once.
  **probe:** while one run holds the lock, a second `terraform plan -lock-timeout=0s` fails with
  `Error acquiring the state lock`. Grep CI and scripts for `-lock=false`: none.
  **Note:** on S3, use `use_lockfile = true` in the backend. Terraform 1.15 marks `dynamodb_table` as deprecated
  ("Use parameter use_lockfile instead"), so a separate DynamoDB lock table is no longer needed.
- **rule:** Split state by domain (network, security, compute, storage, databases), so a change to one can't touch
  another and plans stay fast.
  **probe:** `terraform state list | wc -l` per project stays small; a compute change's plan shows no network
  resources.
- **rule:** A stuck lock is released only with the user's yes, after checking that no run is still going.
  **probe:** **(pause point)** check the lock's ID, who holds it and since when (shown in the lock error), confirm
  no pipeline run is still going, then `terraform force-unlock <ID>`.

## Environments

- **rule:** One directory per environment (`dev/`, `staging/`, `prod/`), each with its own state, variables and
  pipeline. Avoid workspaces for environments: one missed `workspace select` deploys to the wrong place.
  **probe:** each environment directory has its own backend `key`. If workspaces are used anyway, run
  `terraform workspace show` before every plan and say the result to the user.

## Code

- **rule:** No hard-coded IDs or sizes. Values come from variables and `.tfvars`, with a `description`, a `type`
  and a `validation` block for anything a typo could make expensive or dangerous.
  **probe:** grep `.tf` files (not `.tfvars`) for literal IDs (`ami-`, `subnet-`, `sg-`, account IDs, IPs). Pass a bad
  value to a plan: `terraform plan -var instance_type=huge` must fail with your validation message.
- **rule:** Look up changing values (images, zones, account ID) with data sources instead of copying them.
  **probe:** grep for copied image IDs. **Note:** a lookup like `most_recent = true` changes when a new image is
  published, and on many resources a new image ID forces a replace. Check the plan for that replace. Pin the image,
  or use `lifecycle { ignore_changes = [ami] }` and roll new images out on purpose.
- **rule:** Versions are pinned: `required_version`, every provider in `required_providers`, and the
  `.terraform.lock.hcl` file committed.
  **probe:** grep for `required_version` and provider `version` constraints; `git ls-files .terraform.lock.hcl`
  prints the file.
- **rule:** Scripts and config files go in `templatefile()` templates, not long inline strings. No logic in the
  templates.
  **probe:** render without applying: `echo 'templatefile("userdata.tpl", { app = "demo" })' | terraform console`.
- **rule:** A module groups resources that work together (for example a load balancer, autoscaling group and its
  roles). A module around a single resource adds noise.
  **probe:** count `resource "` blocks per module directory; one means reconsider.
- **rule:** Every module has a README: what it does, what it creates, inputs, outputs, an example.
  **probe:** every `modules/*/` directory has a `README.md` listing its variables and outputs.
- **rule:** Code is formatted and valid before review: `fmt` and `validate` run in CI and before every commit.
  **probe:** `terraform fmt -check -recursive` exits `0` (it lists unformatted files and exits `3`);
  `terraform validate` passes in each root.
- **rule:** Collections of named things use `for_each`, not `count`. With `count`, removing one item from the middle
  of a list shifts every later index: Terraform rewrites or replaces them (tested: removing `b` from `["a","b","c"]`
  changed `[1]` and destroyed `[2]`; with `for_each` only `b` was destroyed). Keep `count` for "zero or one".
  **probe:** `grep -rnE '^[[:space:]]*count[[:space:]]*=[[:space:]]*length\(' --include='*.tf' --exclude-dir=.terraform .`
  lists each `count` over a list; each one is a finding.
- **rule:** Refactors use `moved` blocks, giving up management uses `removed` blocks, and adopting existing resources
  uses `import` blocks, all in code and reviewed in a plan. Not `terraform state mv`/`rm`/`import` by hand.
  **probe:** the plan says "has moved to" or "will no longer be managed by Terraform, but will not be destroyed"
  (tested), with `0 to destroy`. `grep -rnE 'terraform (state (mv|rm)|import) ' --include='*.sh' --include='Makefile' --include='*.yaml' --include='*.yml' .`
  finds no scripted state surgery.
- **rule:** Secrets stay out of state. `sensitive = true` only hides a value from the plan output: it is still in the
  state in clear text (tested). Prefer not passing secrets through Terraform at all (the workload reads them from the
  secret manager). When Terraform must set one, use an `ephemeral` variable with a write-only argument (`*_wo`,
  Terraform 1.11 or later) where the provider supports it, so it never reaches state; otherwise mark it `sensitive`
  and treat the state as a secret.
  **probe:** list secret-looking variables and check each is `ephemeral` or `sensitive`:
  `grep -rnE -A4 'variable "[^"]*(password|secret|token|api_?key|private_?key)[^"]*"' --include='*.tf' --exclude-dir=.terraform . | grep -E 'variable "|ephemeral|sensitive'`.
  An output that exposes a sensitive value without `sensitive = true` fails `terraform validate` with "Output refers
  to sensitive values" (tested).
- **rule:** Assumptions are written as code: `validation` on inputs, `precondition`/`postcondition` on resources,
  `check` blocks for things that must stay true, and `terraform test` for every module.
  **probe:** `terraform test` passes in each module that has a `tests/` folder (tested); modules without tests are
  listed: `for d in modules/*/; do [ -d "$d/tests" ] || echo "no tests: $d"; done`. A failing `check` shows as a
  warning in the plan ("Check block assertion failed", tested), so read plan warnings.
- **rule:** Module sources are pinned: a registry module has an exact `version`, a git source has `?ref=` set to a
  tag or commit.
  **probe:** `grep -rnE 'source[[:space:]]*=[[:space:]]*"git::' --include='*.tf' --exclude-dir=.terraform . | grep -v 'ref='`
  prints nothing.
- **rule:** No provisioners or `local-exec` to configure servers: they run outside the plan and can't be reviewed.
  Use images, cloud-init, or a config tool.
  **probe:** `grep -rnE 'provisioner "|null_resource' --include='*.tf' --exclude-dir=.terraform .` prints nothing,
  or each hit has a written reason.
- **rule:** tflint runs with the provider's rule set, not only the default preset, so invalid instance types,
  deprecated arguments and naming are caught.
  **probe:** `.tflint.hcl` exists with `preset = "recommended"` and a `plugin` block for the provider in use
  (`aws`, `azurerm`, `google`); `tflint --init && tflint --recursive` prints no issues.
- **rule:** Plans stay small and whole: no routine `-target`, and each root holds what changes together.
  **probe:** `grep -rnE --include='Makefile' --include='*.sh' --include='*.yaml' --include='*.yml' --exclude-dir=.claude -e '-target[= ]' .`
  prints nothing outside a documented break-glass step.
- **rule:** Every resource the provider can tag gets the standard tags from one place: provider `default_tags`
  (AWS), or a shared `locals` map merged into every `tags`/`labels`.
  **probe:** `grep -rn 'default_tags' --include='*.tf' --exclude-dir=.terraform .`, or the shared tags local; the
  baseline's untagged-resources probe finds nothing.
