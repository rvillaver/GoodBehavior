---
name: devops/shell
use-when: the project has shell scripts (deploy, backup, maintenance, glue); install next to the baseline
---

# Shell scripts: rules for writing and running them safely, each with its probe

Probes marked "tested" were run with bash 5.3, dash and shellcheck 0.11 on macOS. Running a script that changes
anything is a change: it needs the user's yes first, per `devops.md`.

## Before running a script

- **rule:** Assess a script's risk before running it. Read it whole. If it only reads, builds, tests or plans, and
  prints nothing secret, run it. If it changes anything (deletes, moves, restarts, calls a cloud CLI, `kubectl`,
  `terraform apply`, `ssh`, `curl -X POST/PUT/DELETE`) or touches secrets, don't run it yet: tell the user in plain
  words why it needs to run, what it will change, what could go wrong and what it fixes, then ask.
  **probe:** `grep -nE 'rm |mv |kubectl|terraform|helm|aws |az |gcloud|doctl|ssh |curl .*-X|\.secret|\.env' script.sh`
  and show the user what you found. The guard hook does the same check: it reads the script (and scripts it calls,
  and `make` targets) and asks the user when it finds a change or a secret, so a risky line can't hide behind
  `./script.sh` or `make deploy`.

## Safety

- **rule:** Start bash scripts with `set -euo pipefail` (POSIX `sh`: `set -eu`).
  **probe:** `head -5 script.sh` shows it. **Note:** `set -e` alone is not enough (tested): a failed
  pipeline (`missing_cmd | sort`) kept going, and a typo in a variable name (`$tagret_dir/old`) silently became
  `/old`. With `rm -rf` in front, that deletes the wrong path. `set -euo pipefail` stopped both.
- **rule:** Check results by hand where `set -e` doesn't apply: inside a function called from `if`, `&&` or `||`,
  a failure does not stop the script (tested, even with `set -euo pipefail`).
  **probe:** for each function called in a condition, each step that can fail ends in `|| return 1`, or the result
  is checked with `if ! cmd; then ...; fi`.
- **rule:** Scripts that change things do a dry run by default and need `--apply` to make changes.
  **probe:** run without `--apply`; it lists what it would change, and a before/after listing shows nothing changed
  (tested with the template below).
- **rule:** Check inputs up front and stop with a clear message on stderr and a non-zero exit code.
  **probe:** run with a missing argument, a wrong type and a path that doesn't exist; each exits non-zero with a
  message that says what was wrong (tested).
- **rule:** Quote every variable (`"$file"`), and put `--` before paths in `rm`, `mv` and `cp`.
  **probe:** run on a file name with a space in it (tested: `old one.log` was handled). `shellcheck` reports
  unquoted variables as SC2086 (tested).
- **rule:** Never delete with a wildcard outside your own temp folder. Use `mktemp -d` and remove it with a `trap`
  on exit. Guard any delete path built from a variable with `${var:?}` so an empty value stops the script.
  **probe:** `grep -n 'rm -' script.sh`: every target is a quoted variable that is checked, or the `mktemp` folder.
  After a run, the temp folder is gone (tested). **Note:** a cleanup like `cleanup() { rm -rf /tmp/*; }` deletes
  every other program's temp files. Don't copy it.
- **rule:** Running the script twice is safe: the second run changes nothing it already changed.
  **probe:** run the dry run again after an apply; it reports nothing left to do.
- **rule:** No `eval`, and no passwords, tokens or keys in the script. Read them from the environment or a secret
  manager. Don't trace (`set -x`) a section that handles secrets; it prints them.
  **probe:** `grep -n 'eval' script.sh` prints nothing. Run a secret scanner (e.g. `gitleaks detect`) over the repo.

## Readable

- **rule:** First line is a shebang. Then a short header: what the script does, usage, and whether it changes
  anything.
  **probe:** `head -5 script.sh`.
- **rule:** Descriptive names for variables and functions (`log_dir`, `max_age_days`, `backup_files`), not `x` or
  `f`. Comments explain why, not what.
  **probe:** read it: every single-letter name is a short loop counter.
- **rule:** Group steps into functions; one script does one job. Split a script that has grown several jobs.
  **probe:** read it: the main flow at the bottom is a few function calls.
- **rule:** Use `printf` for output, not `echo`, when the text contains variables or escapes.
  **probe:** `grep -nE 'echo -[ne]|echo .*\$' script.sh`.

## Portable

- **rule:** `#!/bin/sh` means POSIX only. If the script uses bash features (`[[ ]]`, arrays, `pipefail`), say so
  with `#!/usr/bin/env bash`.
  **probe:** `dash -n script.sh` catches some bash-only syntax (tested: it caught an array, but not `[[ ]]`).
  `shellcheck -s sh script.sh` catches both (tested: SC3010 for `[[ ]]`, SC3030 for arrays).
- **rule:** Check required tools at the start: `command -v jq >/dev/null || die "jq is required"`. List them in the
  header.
  **probe:** read the header and the first checks; every external tool used is listed and checked.
- **rule:** Lint before committing.
  **probe:** `bash -n script.sh` exits 0 (tested: it caught a missing `fi`). `shellcheck script.sh` exits 0
  (tested: the template below passes clean).

## Template

Tested with bash 5.3 and shellcheck (clean): dry run, bad inputs, a file name with a space, `--apply`, temp folder removed on exit.

```bash
#!/usr/bin/env bash
# rotate-logs.sh: delete .log files older than N days from one directory.
# Usage: rotate-logs.sh [--apply] <log_dir> <max_age_days>
# Without --apply it is a dry run: it lists what it would delete and changes nothing.
set -euo pipefail

usage='usage: rotate-logs.sh [--apply] <log_dir> <max_age_days>'
die() { printf 'error: %s\n' "$1" >&2; exit 1; }

apply=false
if [[ "${1:-}" == "--apply" ]]; then apply=true; shift; fi
log_dir="${1:?$usage}"
max_age_days="${2:?$usage}"

[[ -d "$log_dir" ]] || die "not a directory: $log_dir"
[[ "$max_age_days" =~ ^[0-9]+$ ]] || die "max_age_days must be a whole number: $max_age_days"

# Private scratch space, removed on any exit. Never clean up with a wildcard like /tmp/*.
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

find "$log_dir" -type f -name '*.log' -mtime +"$max_age_days" > "$work_dir/targets"
file_count="$(wc -l < "$work_dir/targets" | tr -d ' ')"

if [[ "$apply" != true ]]; then
  printf 'dry run: would delete %s file(s):\n' "$file_count"
  cat "$work_dir/targets"
  exit 0
fi

while IFS= read -r target_file; do
  rm -- "$target_file"
  printf 'deleted %s\n' "$target_file"
done < "$work_dir/targets"
```
