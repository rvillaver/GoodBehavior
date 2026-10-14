# Project profiles — the on-demand layer

A **profile** fills three slots that make "done" concrete for a *kind* of work:
**the-real-thing** · **verify** (what exercising it like a consumer means) · **evidence** (what proof looks like).

The discipline in `CLAUDE.md` is invariant across every project. Only these three slots change by project type,
because only one thing changes: **what you check the work against to know it's really done — its truth source.**

`/adopt-goodbehavior` reads *this index* up front (cheap), then reads **only the 1–2 closest profile bodies** on
demand — never all five. The other bodies never enter context, and the target project ends up carrying only the
profile(s) it actually uses.

## The five core profiles

| Profile | Truth source | Use when the output is checked against… |
|---|---|---|
| [development](development.md) | code execution / runtime | **running software** — a web app, CLI, service, library, pipeline's build |
| [analysis](analysis.md) | data | a **correct conclusion or dataset** — reports, models, pipelines' output, evals |
| [research](research.md) | external sources / prior art | **claims true to their sources** — literature, market/competitive, investigation, compliance |
| [creative](creative.md) | a human audience | an **artifact that lands** — a deck, long-form writing/docs, a design, marketing |
| [devops](devops.md) | the live environment | **infrastructure in its real state** — cloud/on-prem, IaC, Kubernetes, networking, CI/CD |

## Composable slots

A profile is **not** a rigid single pick. A project can take different slots from different profiles. The canonical
case: a **data pipeline** is *built* like `development` (you write code) but *verified* like `analysis` (correct
output on real input) — so its slots resolve to `build ← development`, `verify ← analysis`, `evidence ← analysis`.
Adopt composes slots; it does not force one label onto the whole project.

## The custom fallback (never "not meant for this project")

If the project matches **none** of the five, adopt does **not** decline. It elicits the three slots directly from the
user — "what's the real thing, how would you check it's right, what would count as proof?" — and writes those as a
custom profile. The five profiles are accelerators; this fallback is the guarantee.
