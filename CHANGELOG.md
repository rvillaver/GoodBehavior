# Changelog

Every entry here is a unit a downstream project will 3-way-merge via `/update-goodbehavior` — write entries so an
adopter skimming before an update knows what's coming and why.

## 2026-10-12 — devops profile: guides, guard, security, cost and code audits

A fifth core profile for infrastructure work, cloud or on-prem. Guides pair every rule with a live probe; a guard
lets investigation run but stops changes and secret leaks.

**Profile** (`templates/profiles/devops.md`)
- Done = the live environment read back from the provider, probed from the consumer's position, re-planned with no
  changes. Every infrastructure change, in any environment, waits for the user's yes, with what it does, what could
  break, how to undo it and what it costs. Plain words for non-experts.
- Secrets live in a gitignored `.secret` file; `.env` and `.secret` are never read.
- Audits run six lenses (wiring, security, reliability, drift, cost, code), then three checklist batches (security,
  cost, code): one row per guide rule (pass, finding, not checked, n/a), plus read-only scanners (gitleaks, trivy,
  checkov, tflint, shellcheck, zizmor/actionlint, jscpd, Prowler, kubescape). Missing scanners are installed only
  after the user's yes. Cost reads the real bill and ends with a savings table. The report always covers security,
  cost and code with counts.

**Guides** (`templates/profiles/devops/`, installed per project as `"devops/<guide>"`)
- `baseline` (IaC, CI/CD, code, secrets, networking, attack surface, observability, backup/DR, cost); tools
  `terraform`, `shell`, `kubernetes`, `helm`; platforms `aws`, `azure`, `gcp`, `digitalocean`, `onprem`.
- Tested corrections to common advice (S3 `use_lockfile`, `set -euo pipefail`, OpenSSL 3 TLS 1.1 probe, Pod Security
  warn vs enforce, billed "stopped" VMs and droplets, open DigitalOcean databases).

**Guard** (`templates/profiles/devops/guard.py`, wired as PreToolUse `*` for devops only)
- Parses each command and what it runs (make recipes, scripts, shell functions, inline Python). **Runs:** reads, plans, tests,
  scans, dry runs, tunnels, ssh and `kubectl exec` commands that only read. **Asks:** changes, installs, anything it
  can't show safe, edits to its own files. **Denies:** anything that would show a secret. Fails closed; bypass mode
  turns ask into deny; logs to `.claude/goodbehavior/guard.log`.
- **Run after a yes:** a stopped command gets a token. Claude asks with the question picker, putting the token in the
  call's hidden `metadata` (the user doesn't see it). A "Yes" lets that exact command run once; editing its script,
  a new user message or a second run needs a new yes. Secrets stay denied.
- Trusted commands: regexes in `.claude/goodbehavior/guard-allow.txt` turn an ask into a run, never a deny.

**Install and update**
- `install.py` takes `devops/<guide>` and `devops/guard.py` and wires PreToolUse only for profiles with a guard.
- `update.py` fix: after a clean merge it recorded the merged content as "untouched", so the next update overwrote
  local edits. It now compares with the upstream version and records upstream hashes only.
- Existing adopters: set the `done-gate.py` PreToolUse matcher to `*`, add `devops/guard.py`, and gitignore
  `.claude/goodbehavior/guard.log`, `.secret` and `files/kubeconfig`.

**Tests:** `test_guard` (653 decisions), `test_hook`, `test_install`, `test_lint` (every rule has a probe),
`test_guide_cli` (every cloud CLI command parses), `test_update`. Probes checked against current AWS, Azure, Google
Cloud and DigitalOcean CLIs, Terraform 1.15, a Debian 12 container and a local Kubernetes 1.35 cluster. Not yet run
against real cloud accounts.

## 2026-07-13 — chat-agents: attach-file + inline-prompt deployment

Some assistants (Copilot observed) **ignore custom instructions**, so standing instructions alone aren't enough. The
`chat-agents/` folder now supports the robust belt-and-suspenders pattern and is single-sourced:
- `chat-agents/goodbehavior.md`: **the** method (attach it, or paste it as instructions) — one source of truth.
- `chat-agents/PROMPT-TEMPLATE.md`: a blank, domain-neutral per-task scaffold that re-states the gate + ✔/⚠ evidence
  rules *inside the task prompt*, where a forgetful agent can't drop them.
- `chat-agents/EXAMPLE.md`: the template filled for one task — domain nouns isolated here so the base stays neutral.
- `chat-agents/README.md`: documents both deployment modes; replaces `PERSONALIZATION.md` (removed — its block became
  `goodbehavior.md`, its usage notes became the README). Top-level README pointer updated.

## 2026-07-12 — chat-only companion

- `chat-agents/PERSONALIZATION.md`: a standalone copy-paste block that carries the operating principles into plain
  Claude.ai chat (no skills, no hook, no filesystem). Audited/enhanced from a user template — adds the gate-vs-drive
  throughline, ✔/⚠ evidence tagging, a done-is-not-self-declared gate, and the unknown-vs-brainstorm distinction; keeps
  the understanding gate and running ledger. All examples are domain-neutral (stated as schema, not instance) so the
  base doesn't prime a frame or infect future variants. Companion only — not installed, not part of the core method.
  README pointer added.

## 2026-07-08 — generalize beyond dev; shrink the trust surface

**Profiles — the method is no longer dev-only.**
- `templates/profiles/`: four composable core profiles (development · analysis · research · creative), each defining
  *the-real-thing / verify / evidence* for its truth source; an INDEX for cheap on-demand loading; a custom-elicit
  fallback. Only the matched profile(s) install into a target — never all four.
- `/adopt-goodbehavior`: new intent-elicitation phase **before** the file survey (what is this project / what does done
  mean / who consumes it / how do you check it's right); the survey is corroboration, not the decider. Adopt must never
  say "GoodBehavior isn't meant for this project."
- Invariant layer reworded artifact-agnostic (CLAUDE.md definition of done, verify/gate-build/audit/roadmap/uatplan
  skills, hook message, templates): "exercised the way its **consumer** would," with the dev phrasing moved into the
  development profile.

**Enforcement — the done-gate is now behavioral, not just lexical.**
- `done-gate.py`: honest hedges always pass; verification vocabulary ("verified", "tests pass") is honored **only if
  something was actually run/observed after the last file change that turn**. "Edited files, ran nothing, said
  'verified'" now blocks. Doc-only turns exempt; bash-only turns pass; sub-agent results don't count as firsthand.

**Determinism — mechanics moved out of prompts into scripts.**
- `scripts/install.py`: adopt's mechanical half (copy, hash, wire the Stop hook without clobbering settings.json, write
  the manifest). Idempotent; never clobbers.
- `scripts/update.py`: update's mechanical half (manifest-driven git 3-way merge; fast-forward / merge / conflict /
  keep-upstream-removed; exit 2 on conflicts).
- The skills keep the judgment (profile resolution, proposals, conflict walkthroughs) and call the scripts.

**Self-test — the bundle held to its own standard.**
- `tests/run_all.py`: hook behavior (14 cases incl. the hollow-proof cheat), install round-trip + idempotency, update's
  four merge paths against a real second commit, structural + drift lint (profiles well-formed; invariant files must not
  re-acquire unscoped dev-coded phrasing). One command; green before shipping.

**Housekeeping.**
- `/adopt-goodbehavior` is no longer copied into targets (run-once installer; targets carry the working skills +
  `/update-goodbehavior`). Seeded memories point at the canonical principles instead of restating them. Stale TODO
  items superseded explicitly.

## 2026-06-28 — promotions from a real adopter

Standing-proceed; ✔/⚠ verified-vs-relayed tagging; adversarial multi-lens audit; `/uatplan-goodbehavior` + UAT template.

## 2026-06-23 — adopt learns deploy ≠ run-locally ≠ verify-target

Adopt analyzes and confirms the three dev-workflow facets separately; flags push-to-branch = deploy; captures the
verify URL.
