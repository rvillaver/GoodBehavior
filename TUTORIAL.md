# Tutorial — how to use GoodBehavior

A practical walkthrough: install the method into a project (new or existing), turn intent into a **plan + checklists**,
then **build it down** under the gated loop until the real thing works — with evidence, user-confirmed.

If you haven't, skim the [README](README.md) for what GoodBehavior *is*. This doc is how you *drive* it.

---

## First, the thing you're worried about: it won't infect your project

Adopting GoodBehavior brings **tools and principles** into your repo — not GoodBehavior's identity. Here's exactly what
crosses the line and what never does:

| Lands in your project (yours now) | Stays in GoodBehavior (never copied) |
|---|---|
| `.claude/skills/*-goodbehavior/` — the skills | This `TUTORIAL.md`, the `README.md` |
| `.claude/hooks/done-gate.py` + its `settings.json` wiring | GoodBehavior's own `TODO.md` (its dev backlog) |
| The **principles** merged into *your* `CLAUDE.md` (or linked from your existing doc) | GoodBehavior's self-dev `docs/` (gitignored anyway) |
| Plan/memory **scaffolding** from `templates/` — which become *your* `ROADMAP.md`, `MEMORY.md`, etc. | The GoodBehavior git history / source repo |
| A `manifest.json` recording where the copy came from (so updates can 3-way-merge) | |

So the only trace of "GoodBehavior" in your repo is the skill **filenames** (`*-goodbehavior`) and the manifest pointer.
Your roadmap, your audit, your learnings, your UAT plan are all about **your project** — written in your project's terms.
The method's meta-docs (this tutorial included) are never dragged along. Adopt **merges into** what you already have
(appends to a CLAUDE.md, links from a HANDOFF.md, maps onto an existing roadmap) — it doesn't impose a parallel structure.

---

## One-time setup: get the bundle

Clone GoodBehavior and open a **Claude Code session inside it** so the skills load:

```bash
git clone <this-repo-url> GoodBehavior
cd GoodBehavior
claude            # open a session here; /adopt-goodbehavior is now available
```

You drive `/adopt-goodbehavior` from *this* session and point it at your project. Every other command
(`/audit-`, `/roadmap-`, `/gate-build-`, …) you run later from a session opened **in your project**, because adopt
installs copies of the skills there.

---

## Step 1 — Adopt: install into a project

```
/adopt-goodbehavior /path/to/your-project
```

Adopt runs four phases and **changes nothing until you confirm**: it *resolves* source + target, *analyzes* your
project, *proposes* a tailored plan **with options**, and only then *installs*.

**Existing project** — the common case. Adopt reads your stack, your workflow, and your existing context docs
(`CLAUDE.md`, `HANDOFF.md`, `README`, `docs/`, any "read this first") and proposes how to integrate: append principles to
your CLAUDE.md or link them from your handoff doc; map planning onto your existing roadmap/issues rather than forking it.

**New / empty project** — initialize the project first (at minimum `git init` and whatever skeleton your stack needs),
then adopt. With little to integrate, it scaffolds fresh: a CLAUDE.md with the principles, and `ROADMAP.md` /
`PRODUCTION-BACKLOG.md` / `MEMORY.md` seeds you'll fill in.

**The one thing to get right when it asks: the dev approach.** Adopt makes you confirm three *separate* things — don't
let them collapse into one:
- **(a) local dev loop** — how you build/run/test on a machine;
- **(b) deploy trigger** — how a change actually ships (a manual command? push-to-branch auto-deploy? which branch?);
- **(c) verify target** — what "verify live" runs *against* (a deployed URL vs localhost).

If deploy is push-triggered, adopt flags that **pushing = deploying** (needs your explicit go-ahead). Your answers get
recorded so later steps use the agreed method, not a guess.

> After adopt, **open a new session in your project** for everything below.

---

## Step 2 — Flesh out the plan

### 2a. Audit — find *all* the gaps (honestly)

```
/audit-goodbehavior
```

Catalogs the concrete delta between what exists and what's wanted, **cross-checked against a reference** (a design, a
spec, a competitor, a demo) — element by element, grounded in the real code/screens you just looked at, not memory. It's
deliberately **gated in batches** (one area per pass, reviewed before the next) so you get depth, not a shallow
everything-at-once list. Each gap is severity-tagged (P0/P1/P2) and carries a **verification tag**: `✔` confirmed
firsthand vs `⚠` relayed/still-to-confirm. For anything important, it runs **multiple independent lenses**
(security · coverage vs intended journeys · completeness/wiring · flow/UX · coherence) and treats a contradiction between
two lenses as its own finding. Output lives under `docs/audit/`.

### 2b. Roadmap — order the work by leverage

```
/roadmap-goodbehavior
```

Rolls the gaps into a sequenced, **phased** plan in `docs/plans/ROADMAP.md` — systemic/cheap/high-visibility first, then
foundational, then per-area, then content. Low-ROI / blocked / out-of-scope work is parked (with *why* and *what unblocks
it*) in `docs/plans/PRODUCTION-BACKLOG.md`. The current phase is tagged **NOW**. Every item carries its definition of
done and how it'll be verified — never "spec green."

### 2c. UAT plan — the checklists (how each feature is tested)

```
/uatplan-goodbehavior
```

Builds a **living manual user-test map** in `docs/qa/UAT-PLAN.md`: every feature set, the exact steps a human follows on
the **real app**, the expected result (UI *and* backend effect), and a `[ ] Pass / [ ] Fail` checkbox to close each one.
Organized by feature area (and by role, with a permutation matrix, where roles exist). This is the durable counterpart to
automated tests — it catches what unit tests can't — and it's what the build step verifies against. Keep it current as
features ship.

---

## Step 3 — Build, gated (plans + checklists → working software)

```
/gate-build-goodbehavior
```

Works the **NOW** phase of the roadmap, **one item at a time**, to the real definition of done:

1. **Build** the smallest change that actually closes the gap (reuse before hand-rolling).
2. **Deploy/run** it your project's real way.
3. **Verify live** (`/verify-goodbehavior`) — drive the actual flow through the real UI *and* backend like a user, and
   capture evidence. Mark the matching UAT case `[ ] Pass → ✔`. **A green test alone is not verification.**
4. **Record learnings** (`/learn-goodbehavior`) — any non-obvious trap/correction/build-deploy fact, so it isn't
   relearned next session.
5. **Status** — mark the item done **only with evidence** (`✔`); otherwise "partial/blocked" (`⚠`) and log the blocker.

**Gate before the next phase:** loop the phase until *every* item has concrete evidence (or is explicitly backlogged).
A phase never advances on a `⚠` item. Don't sidetrack — log tangents to the backlog and keep the throughline.

### Standing-proceed — going faster once you trust it

After you've watched the gates hold — done means done, verification is real, reports are honest — you can grant
**standing-proceed**: tell the agent to run the plan **unattended**, without stopping to ask after every item. This is
*not* a shortcut past the checks: every item still builds → verifies live → records → gates exactly as before. It only
removes the *pause between items*. The loop pauses to ask **only** for a genuine design decision, a real failure, or a
destructive/irreversible step (a push that deploys, a migration). It's an earned escalation of trust — give it once you
have the confidence, take it back the moment you don't.

---

## Step 4 — Report honestly / what "done" means

The bar for done is high on purpose: **the real thing works end-to-end, with evidence, and *you* confirmed it.** Not a
passing spec, not a screenshot, not a confident summary. Until you've confirmed it, the honest status is **"not done
yet."** The `done-gate.py` Stop hook nudges back when a turn claims "done" without showing evidence — a heuristic
backstop, not a lie detector. *You* are the real done-gate.

---

## Step 5 — Stay current with the method

```
/update-goodbehavior
```

Because your install is a **copy** (so you could adapt it), it won't auto-drift as GoodBehavior improves. `update` reads
your manifest, fetches the source, and for each tracked file does a **git 3-way merge** — untouched files fast-forward,
files you adapted get merged, genuine conflicts get markers for you to resolve. Your local adaptations survive; upstream
improvements flow in. Human-in-the-loop on conflicts.

---

## The whole loop at a glance

```
            ┌─────────────────────────── (once) ───────────────────────────┐
  /adopt ──►│  /audit  ──►  /roadmap  ──►  /uatplan                         │
            └───────────────────────────────┬─────────────────────────────-┘
                                             ▼
                         ┌──────────  /gate-build (NOW phase)  ──────────┐
                         │  build → /verify (live) → /learn → gate        │ ◄─ loop the
                         │  mark UAT case ✔ ; never advance on ⚠          │     phase
                         └───────────────────────┬──────────────────────-┘
                                                 ▼
                                    report honestly → you confirm → done
                                                 │
                                  (later)  /update  ◄── pull method improvements
```

**Rules that hold the whole way through:** ground claims in what you just looked at (not memory); tag findings `✔`
verified vs `⚠` relayed and never build on a `⚠`; verify the real behavior, not a proxy; record learnings so you don't
relearn them; and never self-declare done.
