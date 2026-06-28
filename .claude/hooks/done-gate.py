#!/usr/bin/env python3
"""GoodBehavior done-gate — a Stop hook that pushes back on self-declared "done".

When the last assistant message makes an explicit completion claim *without* any sign of evidence,
verification, or a hedge, it blocks the stop once and feeds back a short self-check. It is a heuristic
nudge, not a lie detector: conservative claim-matching to limit false positives, and a single fire per
turn (the stop_hook_active guard prevents loops).

False-positive controls, in the order they short-circuit:
  (3) Activity gate  — only arm when THIS turn actually touched code/build (Edit/Write/Bash/...).
                       Pure discussion turns never trip the gate.
  (1) Meta escape    — talking ABOUT the gate/framework ("done-gate", "the hook") isn't a claim.
  (2) Assertive only — the completion word must head a short declarative clause, not just appear
                       somewhere in a long paragraph.
  (0) Evidence/hedge — verification or an honest hedge in the message lets the stop through.

Wire as a Stop hook in .claude/settings.json. Requires only python3.
"""
import sys, json, re

# Tools whose use means the turn did real build work (lowercased).
BUILD_TOOLS = {"edit", "write", "multiedit", "notebookedit", "applypatch", "bash"}

# Explicit completion claims (kept narrow on purpose).
CLAIM = re.compile(
    r"(✅|\bit'?s (now )?(done|complete|working)\b|\b(all )?(done|complete|completed|finished|shipped)\b"
    r"|\bworks now\b|\bfully (working|functional)\b|\bgood to go\b|\ball set\b)")

# Signs of evidence / verification / honest hedging → let it through.
EVIDENCE = re.compile(
    r"(verif|screenshot|i ran|ran the|test(s)? pass|passing|confirm|evidence|rendered|observed"
    r"|not (yet|done)|isn't done|partial|in progress|pending|blocked|deferred|backlog|to verify"
    r"|please (check|review|confirm)|you (can )?(check|confirm)|left to do|remaining)")

# (1) Meta-discussion about the gate/framework itself — not a real completion claim.
META = re.compile(
    r"(done-gate|good ?behavior|the (gate|hook)|this hook|stop hook|the regex"
    r"|false (positive|trigger))")


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # never break the session on a parse error

    # Don't re-fire on our own continuation (avoids an infinite stop loop).
    if data.get("stop_hook_active"):
        sys.exit(0)

    path = data.get("transcript_path", "")
    entries = load_entries(path)

    text = last_assistant_text(entries)
    if not text:
        sys.exit(0)
    t = text.lower()

    # (3) Activity gate: a turn that didn't build anything can't have "finished" anything.
    if not built_this_turn(entries):
        sys.exit(0)

    # (1) Meta escape: discussing the gate/framework uses words like "done" incidentally.
    if META.search(t):
        sys.exit(0)

    # (2) Assertive only: the claim must head a short clause, not lurk in a long sentence.
    if not assertive_claim(text):
        sys.exit(0)

    # (0) Evidence / verification / honest hedge present → fine to stop.
    if EVIDENCE.search(t):
        sys.exit(0)

    sys.stderr.write(
        "GoodBehavior done-gate — you claimed completion. Before ending, self-check:\n"
        "  1) Did you exercise the REAL behavior (UI + backend), not just a test/your description?\n"
        "  2) Can you SHOW the evidence (rendered result vs. reference; the flow firing)?\n"
        "  3) Is it user-confirmed? If not, say \"not done yet\" / state what's left — don't self-declare done.\n"
        "Then either present the evidence, soften the claim, or record a learning and continue.\n")
    sys.exit(2)  # blocks the stop; stderr is returned to the model


def assertive_claim(text):
    """A completion word counts only inside a short, declarative clause — not buried in prose."""
    for raw in re.split(r"[.!?\n]+", text):
        s = raw.strip()
        if not s:
            continue
        if len(s.split()) > 12:
            continue  # incidental mention inside a longer sentence
        if CLAIM.search(s.lower()):
            return True
    return False


def entry_role(e):
    msg = e.get("message", e)
    return e.get("role") or msg.get("role") or e.get("type")


def is_human_turn(e):
    """A real human message — not a tool_result (which the transcript also stores as role 'user')."""
    if entry_role(e) != "user":
        return False
    content = e.get("message", e).get("content", "")
    if isinstance(content, str):
        return bool(content.strip())
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip()
                   for b in content)
    return False


def built_this_turn(entries):
    """Did the assistant use a build tool since the last human message (this turn)?"""
    last_human = -1
    for i, e in enumerate(entries):
        if is_human_turn(e):
            last_human = i
    for e in entries[last_human + 1:]:
        if entry_role(e) != "assistant":
            continue
        content = e.get("message", e).get("content", "")
        if isinstance(content, list):
            for b in content:
                if (isinstance(b, dict) and b.get("type") == "tool_use"
                        and (b.get("name") or "").lower() in BUILD_TOOLS):
                    return True
    return False


def last_assistant_text(entries):
    last = ""
    for e in entries:
        if entry_role(e) != "assistant":
            continue
        content = e.get("message", e).get("content", "")
        if isinstance(content, str):
            txt = content
        elif isinstance(content, list):
            txt = " ".join(b.get("text", "") for b in content
                           if isinstance(b, dict) and b.get("type") == "text")
        else:
            txt = ""
        if txt.strip():
            last = txt
    return last


def load_entries(path):
    if not path:
        return []
    out = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out


if __name__ == "__main__":
    main()
