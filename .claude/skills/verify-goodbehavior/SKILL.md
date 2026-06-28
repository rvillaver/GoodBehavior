---
name: verify-goodbehavior
description: Verify a change by exercising the REAL behavior — run the app and drive the actual flow (UI + backend) like a user, then capture evidence. Self-contained (no dependency on other skills). Use to confirm a change works before calling it done; a passing test alone does not count.
---

Prove a change actually does what it's supposed to by observing real behavior — not by reading the diff, not by a green
test, not by describing it. This skill is self-contained: it does not call other skills.

## Procedure
1. **Know the intended behavior** — what should a user see/get after this change? State it in one sentence.
2. **Run the real thing** — start/serve/deploy the app the project's real way (see CLAUDE.md "stack" notes /
   `build-deploy-gotchas`). Confirm you're hitting the **current build**, not a stale cache/old bundle.
3. **Drive the actual flow** — perform the user's steps end to end (navigate, fill, submit, click), through the UI and
   the backend it calls. Use whatever's available: a browser/automation tool, the running app, real requests.
4. **Capture evidence** — a screenshot/recording of the result (ideally beside the reference), and/or the real
   response/output showing the flow fired (e.g. the record was created, the count changed, the state advanced).
5. **Compare to intent** — does the observed behavior match step 1 and the reference? Note any delta.

## Report honestly
- If it matches: present the **evidence**, and frame it as **"verified — your confirmation needed,"** not "done." The
  user is the done-gate.
- If it doesn't: say so with the actual failure (message/screenshot), and either fix or log it.
- If you couldn't run it live (blocked/no access): say that plainly — do **not** substitute a passing test or your
  description for live verification. Record the blocker.

> If the project keeps a UAT plan (`/uatplan-goodbehavior`), drive the relevant case(s) from it and record the
> Pass/Fail there — verify proves the change live; the UAT plan is where that evidence persists and stays auditable.

## Anti-patterns (these are NOT verification)
- "Tests pass" / "build succeeded" → necessary, not sufficient.
- "I changed the code so it should work."
- A screenshot of a cached/old build.
- Narrating the expected behavior without observing it.
