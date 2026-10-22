---
name: devops/python
use-when: the project has Python ops scripts (automation, glue, maintenance, exporters); install next to the baseline
---

# Python scripts: rules for writing and running them safely, each with its probe

The same discipline as `shell.md`, for Python. Probes marked "tested" were run in October 2026 with ruff 0.12 and
bandit 1.8 (installed in a throwaway Python container) on a sample script. Running a script that changes anything
is a change: it needs the user's yes first, per `devops.md`.

Without the tools installed, run them in a container, so nothing is installed on the machine:
`docker run --rm -v "$PWD":/src -w /src python:3.13-slim sh -c 'pip install -q ruff bandit && ruff check --select F,E9,S,B . && bandit -q -r .'`.

## Safety

- **rule:** Scripts pass ruff (with the security `S` and bug `B` rules) and bandit.
  **probe:** `ruff check --select F,E9,S,B .` and `bandit -q -r .` print no findings, or each has a written reason
  (tested: they flagged a hard-coded password, `shell=True` and a web request with no timeout).
- **rule:** No passwords, tokens or keys in the code. Read them from the environment or the secret manager, and
  never print or log them.
  **probe:** bandit B105/B106 and ruff S105/S106 don't appear (tested); the baseline's gitleaks probe finds nothing.
- **rule:** Run programs with an argument list, never `shell=True` with built-up strings.
  **probe:** `grep -rn 'shell=True' --include='*.py' .` prints nothing (bandit B602, tested).
- **rule:** Every network call has a timeout, so a hung endpoint doesn't hang the script or the job running it.
  **probe:** ruff S113 / bandit B113 don't appear (tested).
- **rule:** Scripts that change things do a dry run by default and need `--apply` to act, check their inputs up
  front, and exit non-zero with a clear message on failure.
  **probe:** run with no arguments and with `--help`: it prints usage and changes nothing. Run without `--apply`:
  it lists what it would do, and a before/after read shows nothing changed.

## Repeatable

- **rule:** Dependencies are pinned (a lock file, or `==` versions in `requirements.txt`) and installed in a
  virtual environment, not the system Python.
  **probe:** `grep -vnE '==|^#|^$' requirements*.txt` prints nothing, or a lock file (`uv.lock`, `poetry.lock`) is
  committed.
- **rule:** The entry point is a `main()` behind `if __name__ == "__main__":`, using `argparse` for options, so the
  script can be imported and tested.
  **probe:** `grep -nE '__name__ == .__main__.|argparse' <script>.py` finds both.
