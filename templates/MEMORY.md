# Memory index

One line per durable learning, loaded each session. One fact per file (see `/learn-goodbehavior` for the per-file schema). Seed the
two behavioral non-negotiables below on init; add `gotcha`/`project`/`reference` entries as they're discovered.

- [Definition of done](definition-of-done.md) — done = real thing working + evidence + user-confirmed; no single proxy; never self-declare
- [Reporting honesty](reporting-honesty.md) — claim only what you can show; surface failures/blockers; state partial/deferred plainly
- [Build/deploy gotchas](build-deploy-gotchas.md) — project-specific traps (caching, drift, bundled-vs-runtime config, seeded access…); check BEFORE diagnosing

<!-- Seed files to create alongside this index:

definition-of-done.md
---
name: definition-of-done
description: What "done" means here — the binding bar for completion
metadata: { type: feedback }
---
Done = the real behavior works end-to-end (UI + backend), with shown evidence, and the user confirms it. A passing
test, a screenshot, or a confident summary is NOT done — no single proxy counts. Default to "not done yet"; never
self-declare done. **Why:** the recurring failure is collapsing a whole task to one cheatable proxy.

reporting-honesty.md
---
name: reporting-honesty
description: How to report status honestly
metadata: { type: feedback }
---
Claim only what you can show. "Tests pass" ≠ "it works"; "I changed the code" ≠ "behavior changed." Surface real
failure output, state skipped steps, name blockers and log them, mark partial/deferred plainly. **Why:** false/lazy
claims erode trust and hide real work left to do.

build-deploy-gotchas.md  (start empty; fill via /learn-goodbehavior as traps are found)
-->
