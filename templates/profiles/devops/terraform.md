---
name: devops/terraform
use-when: the project uses Terraform or OpenTofu; install next to the baseline and the provider guides
---

# Terraform: rules for a safe apply, each with its probe

Every probe below was run against Terraform 1.15. Probes are read-only unless marked **(pause point)**: those need the
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
