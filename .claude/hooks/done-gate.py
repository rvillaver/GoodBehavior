#!/usr/bin/env python3
"""GoodBehavior done-gate — a Stop hook that pushes back on self-declared "done".

When the last assistant message makes an explicit completion claim without support, it blocks the
stop once and feeds back a short self-check. It is a heuristic nudge, not a lie detector: conservative
claim-matching to limit false positives, and a single fire per turn (the stop_hook_active guard
prevents loops).

Two layers:
  LEXICAL    — what the message says. An honest hedge ("not done yet", "unverified") always lets the
               stop through. Verification vocabulary ("verified", "I ran", "tests pass") is only a
               *claim* of proof.
  BEHAVIORAL — what the turn actually did. Verification vocabulary is honored only if something was
               actually run/observed AFTER the last file change this turn (a command, a fetch, a
               browser drive). "Edited files, ran nothing, said 'verified'" blocks: the final state
               of the work was never observed, so the proof-claim is hollow.

False-positive controls, in the order they short-circuit:
  (3) Activity gate  — only arm when THIS turn actually touched code/build (Edit/Write/Bash/...).
                       Pure discussion turns never trip the gate.
  (1) Meta escape    — talking ABOUT the gate/framework ("done-gate", "the hook") isn't a claim.
  (2) Assertive only — the completion word must head a short declarative clause, not just appear
                       somewhere in a long paragraph.
  (0a) Hedge         — an honest downgrade in the message always lets the stop through.
  (0b) Proof+observed — verification vocabulary + an observation after the last change lets it through.
       Doc-only turns (every mutation touched .md/.txt/...) are exempt from the behavioral check:
       there is often nothing to "run" for prose, so proof vocabulary suffices there.

Profile questions: an installed profile (.claude/goodbehavior/profiles/*.md) may carry "### gate: <mode>"
sections — "match:" regexes (one per line) of commands that change things, "claims:" regexes of extra
claim phrases, and "- " question bullets. A turn that changed files or ran a match: command is "change";
any other turn is "investigation". When the turn's mode has questions, they replace the generic
self-check. No such sections → the generic messages below, unchanged.

Guard (PreToolUse on Bash, Read, Grep): reads the profile's "### gate: change" and "### gate: secrets"
sections. A command that matches a change "match:" line, or hides one inside a make target, a script or
inline code (followed a few levels deep), gets "ask": the user must approve it. A command that would print
a secret (a secrets "match:" line, or a reader such as cat/grep pointed at a secrets "files:" path), or a
Read/Grep of such a file, gets "deny". Writing to a secret file without reading it is allowed. An edit
(Edit/Write tools or a shell write) to a "### gate: protect" "files:" path, such as the hooks and settings,
gets "ask". Anything else runs. No gate sections → no-op.

Wire as a Stop hook (and a PreToolUse hook for Bash) in .claude/settings.json. Requires only python3.
"""
import glob, importlib.util, os, sys, json, re, shlex

# Tools whose use means the turn did real build work (lowercased) — arms the gate.
BUILD_TOOLS = {"edit", "write", "multiedit", "notebookedit", "applypatch", "bash"}

# Tools that MUTATE files (for the behavioral check: what was the last change?).
MUTATION_TOOLS = {"edit", "write", "multiedit", "notebookedit", "applypatch"}

# Tools whose use counts as OBSERVING real behavior (running/fetching/driving something).
# Sub-agent results (task/agent) are relayed claims, not firsthand observation — excluded on purpose.
OBSERVE_TOOLS = {"bash", "webfetch"}
OBSERVE_NAME_HINTS = ("browser", "puppeteer", "playwright", "chrome")

# File extensions where "run it" usually doesn't apply — prose/docs. Doc-only turns skip the
# behavioral check (lexical proof suffices).
DOC_EXTENSIONS = (".md", ".markdown", ".txt", ".rst", ".adoc")

# Explicit completion claims (kept narrow on purpose).
CLAIM = re.compile(
    r"(✅|\bit'?s (now )?(done|complete|working)\b|\b(all )?(done|complete|completed|finished|shipped)\b"
    r"|\bworks now\b|\bfully (working|functional)\b|\bgood to go\b|\ball set\b)")

# (0a) Honest hedge / downgrade — always let the stop through; honesty must never be punished.
HEDGE = re.compile(
    r"(not (yet|done)|isn't done|unverified|partial|in progress|pending|blocked|deferred|backlog"
    r"|to verify|still to|left to do|remaining|please (check|review|confirm)|you (can )?(check|confirm))")

# (0b) Verification vocabulary — a *claim* of proof; honored only when backed by behavior.
PROOF = re.compile(
    r"(verif|screenshot|i ran|ran the|test(s)? pass|passing|confirm|evidence|rendered|observed)")

# (1) Meta-discussion about the gate/framework itself — not a real completion claim.
META = re.compile(
    r"(done-gate|good ?behavior|the (gate|hook)|this hook|stop hook|the regex"
    r"|false (positive|trigger))")

MSG_NO_EVIDENCE = (
    "GoodBehavior done-gate — you claimed completion. Before ending, self-check:\n"
    "  1) Did you exercise the REAL thing the way its consumer would (per the project's profile) — not just a test/your description?\n"
    "  2) Can you SHOW the evidence (result vs. reference; the flow firing / validation output / source-backed claim)?\n"
    "  3) Is it user-confirmed? If not, say \"not done yet\" / state what's left — don't self-declare done.\n"
    "Then either present the evidence, soften the claim, or record a learning and continue.\n")

MSG_HOLLOW_PROOF = (
    "GoodBehavior done-gate — you claim verification, but this turn ran/observed NOTHING after its last\n"
    "file change: the final state of the work was never exercised. Either actually run/observe the real\n"
    "thing now (per the project's profile) and show the result, or downgrade the claim to \"unverified /\n"
    "not done yet\" and say what's left. A proof-word without an observation is the exact failure this\n"
    "method exists to stop.\n")


def format_questions(questions):
    return "".join(f"  {i}) {q}\n" for i, q in enumerate(questions, 1))


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # never break the session on a parse error

    if data.get("hook_event_name") == "PreToolUse":
        if not profile_guard(data):
            guard(data)
        sys.exit(0)

    # Don't re-fire on our own continuation (avoids an infinite stop loop).
    if data.get("stop_hook_active"):
        sys.exit(0)

    path = data.get("transcript_path", "")
    entries = load_entries(path)

    text = last_assistant_text(entries)
    if not text:
        sys.exit(0)
    t = text.lower()

    tools = turn_tool_uses(entries)
    gates = load_gates(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or "")
    mode = turn_mode(tools, gates)
    gate = gates.get(mode, {})
    questions = gate.get("questions") or []

    # (3) Activity gate: a turn that didn't build anything can't have "finished" anything.
    if not any(name in BUILD_TOOLS for name, _ in tools):
        sys.exit(0)

    # (1) Meta escape: discussing the gate/framework uses words like "done" incidentally.
    if META.search(t):
        sys.exit(0)

    # (2) Assertive only: the claim must head a short clause, not lurk in a long sentence.
    if not assertive_claim(text, gate.get("claims") or []):
        sys.exit(0)

    # (0a) An honest hedge always passes — never punish the downgrade.
    if HEDGE.search(t):
        sys.exit(0)

    # (0b) Verification vocabulary passes only when the behavior backs it.
    if PROOF.search(t):
        if doc_only_mutations(tools) or observed_after_last_mutation(tools):
            sys.exit(0)
        sys.stderr.write(MSG_HOLLOW_PROOF + (f"Also answer ({mode}):\n" + format_questions(questions)
                                             if questions else ""))
        sys.exit(2)

    if questions:
        what = "a conclusion" if mode == "investigation" else "completion"
        sys.stderr.write(f"GoodBehavior done-gate — you claimed {what}. Before ending, answer the project "
                         f"profile's {mode} questions:\n" + format_questions(questions)
                         + "Then show the evidence, soften the claim, or say what's left.\n")
        sys.exit(2)
    sys.stderr.write(MSG_NO_EVIDENCE)
    sys.exit(2)  # blocks the stop; stderr is returned to the model


def assertive_claim(text, extra=None):
    """A completion word counts only inside a short, declarative clause — not buried in prose.
    `extra` is a profile's list of additional claim patterns (e.g. an investigation's conclusion phrases)."""
    for raw in re.split(r"[.!?\n]+", text):
        s = raw.strip()
        if not s:
            continue
        if len(s.split()) > 12:
            continue  # incidental mention inside a longer sentence
        if CLAIM.search(s.lower()) or any(x.search(s.lower()) for x in extra or []):
            return True
    return False


def load_gates(project_dir):
    """{mode: {"match": [re], "claims": [re], "files": [re], "questions": [str]}} from installed profiles."""
    gates = {}
    folder = os.path.join(project_dir, ".claude", "goodbehavior", "profiles") if project_dir else ""
    try:
        names = sorted(n for n in os.listdir(folder) if n.endswith(".md"))
    except Exception:
        return gates
    for n in names:
        try:
            with open(os.path.join(folder, n)) as f:
                lines = f.read().splitlines()
        except Exception:
            continue
        cur = None
        for ln in lines:
            m = re.match(r"^#{1,6}\s+gate:\s*(\w+)", ln)
            if m:
                cur = gates.setdefault(m.group(1).lower(), {"match": [], "claims": [], "files": [], "questions": []})
                continue
            if cur is None:
                continue
            if ln.startswith("#"):
                cur = None
            elif ln.startswith(("match:", "claims:", "files:")):
                key, _, pat = ln.partition(":")
                try:
                    cur[key].append(re.compile(pat.strip(), re.I))
                except re.error:
                    pass  # a bad pattern in a profile must never break the session
            elif ln.startswith("- "):
                cur["questions"].append(ln[2:].strip())
            elif ln.startswith("  ") and ln.strip() and cur["questions"]:
                cur["questions"][-1] += " " + ln.strip()
    return gates


def changes_things(cmd, gates):
    return any(m.search(str(cmd)) for m in gates.get("change", {}).get("match", []))


def turn_mode(tools, gates):
    """"change" if the turn mutated files or ran a profile match: command, else "investigation"."""
    for name, tool_input in tools:
        if name in MUTATION_TOOLS:
            return "change"
        cmd = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        if name == "bash" and changes_things(cmd, gates):
            return "change"
    return "investigation"


# Shell parsing for the guard: split a line into command segments, strip wrappers, find what runs.
SEGMENT_SPLIT = re.compile(r"\|\||&&|[;\n|&]")
WRAPPERS = {"sudo", "env", "nohup", "nice", "command", "exec", "time", "xargs", "timeout"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
INTERPRETERS = SHELLS | {"python", "python3", "node", "ruby", "perl"}
# Commands that print what they read: pointing one at a secret file puts the secret in the conversation.
READERS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "awk", "gawk", "cut", "strings",
           "xxd", "od", "hexdump", "base64", "jq", "yq", "sort", "uniq", "nl", "tac", "bat", "diff", "sed", "tr",
           "python", "python3", "node", "ruby", "perl", "column", "fold", "paste", "rev", "vi",
           "vim", "nano", "emacs", "view", "cp", "scp", "rsync", "curl", "nc", "openssl", "gpg", "zip", "tar"}
MAX_DEPTH = 3
MAX_SCRIPT_BYTES = 200_000


def segments(line):
    """Each command segment of a shell line as a token list, with wrappers and VAR=val stripped."""
    out = []
    for seg in SEGMENT_SPLIT.split(line):
        try:
            toks = shlex.split(seg, comments=True)
        except ValueError:
            toks = seg.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            assignment = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", t)
            if assignment or t in WRAPPERS or (t.startswith("-") and i and toks[i - 1] in WRAPPERS):
                i += 1
            elif i and toks[i - 1] == "timeout" and re.fullmatch(r"[0-9.]+[smhd]?", t):
                i += 1
            else:
                break
        if toks[i:]:
            out.append(toks[i:])
    return out


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_SCRIPT_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def make_rules(directory, makefile=None):
    """(vars, rules, default) from a Makefile and its static includes. rules: target -> (prereqs, recipe lines)."""
    names = [makefile] if makefile else ["GNUmakefile", "makefile", "Makefile"]
    path = next((os.path.join(directory, n) for n in names if os.path.isfile(os.path.join(directory, n))), None)
    variables, rules, default, seen = {"MAKE": "make"}, {}, None, set()

    def parse(p):
        nonlocal default
        if p in seen or not os.path.isfile(p):
            return
        seen.add(p)
        text = (read_text(p) or "").replace("\\\n", " ")
        current = None
        for raw in text.splitlines():
            if raw.startswith("\t"):
                if current:
                    for t in current:
                        rules.setdefault(t, ([], []))[1].append(raw.strip().lstrip("@-+"))
                continue
            line = raw.split("#", 1)[0].rstrip()
            inc = re.match(r"^-?(include|sinclude)\s+(.+)$", line)
            m_var = re.match(r"^(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:=|::=|\+=|=)\s*(.*)$",
                             line)
            m_rule = re.match(r"^([^:=#\t][^:=#]*?)\s*::?\s*([^=].*)?$", line)
            if inc:
                for f in inc.group(2).split():
                    parse(os.path.join(directory, expand(f, variables)))
                current = None
            elif m_var:
                name, op, val = m_var.groups()
                if op == "?=" and name in variables:
                    pass
                elif op == "+=":
                    variables[name] = (variables.get(name, "") + " " + val).strip()
                else:
                    variables[name] = val
                current = None
            elif m_rule and not line.startswith((" ", "\t")):
                targets = [t for t in expand(m_rule.group(1), variables).split() if "%" not in t]
                prereqs = expand((m_rule.group(2) or "").split(";")[0].split("|")[0], variables).split()
                for t in targets:
                    rules.setdefault(t, ([], []))[0].extend(prereqs)
                    if default is None and not t.startswith("."):
                        default = t
                current = targets
            elif line.strip():
                current = None

    if path:
        parse(path)
    return variables, rules, default


def expand(text, variables, depth=0):
    if depth > 8:
        return text
    out = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]", lambda m: variables.get(m.group(1), m.group(0)), text)
    return out if out == text else expand(out, variables, depth + 1)


def make_lines(tokens, cwd, depth):
    """Recipe lines a `make ...` call would run, following prerequisites and recursive make calls."""
    directory, makefile, targets, i = cwd, None, [], 1
    while i < len(tokens):
        t = tokens[i]
        if t in ("-C", "--directory", "-f", "--file", "--makefile") and i + 1 < len(tokens):
            if t in ("-C", "--directory"):
                directory = os.path.join(directory, tokens[i + 1])
            else:
                makefile = tokens[i + 1]
            i += 2
            continue
        if t.startswith(("--directory=", "--file=", "--makefile=")):
            key, _, val = t.partition("=")
            directory, makefile = (os.path.join(directory, val), makefile) if key == "--directory" else (directory, val)
        elif not t.startswith("-") and "=" not in t and not t.isdigit():
            targets.append(t)
        i += 1
    variables, rules, default = make_rules(directory, makefile)
    lines, visited = [], set()

    def walk(target):
        if target in visited or target not in rules:
            return
        visited.add(target)
        prereqs, recipe = rules[target]
        for p in prereqs:
            walk(p)
        for r in recipe:
            lines.append((f"Makefile:{target}", expand(r, variables), directory))

    for t in targets or ([default] if default else []):
        walk(t)
    return lines


def script_path(tokens, cwd):
    """The local script file a segment runs, if any (`./x.sh`, `bash x.sh`, `python3 x.py`)."""
    head = os.path.basename(tokens[0])
    if head in INTERPRETERS:
        args = [t for t in tokens[1:] if not t.startswith("-")]
        if any(t in ("-c", "-e") for t in tokens[1:]) or not args:
            return None
        candidate = args[0]
    elif "/" in tokens[0]:
        candidate = tokens[0]
    else:
        return None
    path = os.path.join(cwd, os.path.expanduser(candidate))
    return path if os.path.isfile(path) else None


def inline_code(tokens):
    """Code passed inline: `bash -c "..."`, `python3 -c "..."`, `node -e "..."`."""
    for flag in ("-c", "-e"):
        if os.path.basename(tokens[0]) in INTERPRETERS and flag in tokens[1:]:
            i = tokens.index(flag)
            if i + 1 < len(tokens):
                return tokens[i + 1]
    return None


def expanded_lines(command, cwd, depth=0):
    """(where, line, cwd) for the command itself plus every line it would run: make recipes, scripts, inline code."""
    found = [("command", command, cwd)]
    if depth >= MAX_DEPTH:
        return found
    for toks in segments(command):
        head = os.path.basename(toks[0])
        sub = []
        if head in ("make", "gmake"):
            sub = make_lines(toks, cwd, depth)
        else:
            path = script_path(toks, cwd)
            code = inline_code(toks)
            if path:
                text = read_text(path) or ""
                rel = os.path.relpath(path, cwd)
                sub = [(f"{rel}:{n}", ln.strip(), cwd) for n, ln in enumerate(text.splitlines(), 1)
                       if ln.strip() and not ln.strip().startswith("#")]
            elif code:
                sub = [("inline", ln.strip(), cwd) for ln in code.splitlines() if ln.strip()]
        for where, line, d in sub:
            for w2, l2, d2 in expanded_lines(line, d, depth + 1):
                found.append((where if w2 == "command" else w2, l2, d2))
    return found


def secret_file(path, gates):
    return any(m.search(path) for m in gates.get("secrets", {}).get("files", []))


def reads_secret_file(command, gates):
    """A reader command pointed at a secret file (or `< secret`). Writes (`>> .env`, `sed -i`) are fine."""
    for toks in segments(command):
        head = os.path.basename(toks[0])
        args = toks[1:]
        if head == "sed" and any(a == "-i" or a.startswith(("-i", "--in-place")) for a in args):
            continue
        if head in READERS and any(secret_file(a, gates) for a in args if not a.startswith("-")):
            return True
        redirect_in = re.search(r"<\s*(\S+)", " ".join(toks))
        if redirect_in and secret_file(redirect_in.group(1), gates):
            return True
    return False


WRITERS = {"cp", "mv", "rm", "ln", "chmod", "chown", "truncate", "tee", "install", "rsync", "dd", "unlink", "touch"}


def protected_file(path, gates):
    return any(m.search(path) for m in gates.get("protect", {}).get("files", []))


def writes_protected_file(command, gates):
    """A shell write aimed at a protected file: a redirect, a writer command, `sed -i`/`perl -i`, or inline code
    that names the file."""
    for target in re.findall(r">{1,2}\|?\s*([^\s;&|<>]+)", command):
        if protected_file(target, gates):
            return True
    for toks in segments(command):
        head = os.path.basename(toks[0])
        args = [a for a in toks[1:] if not a.startswith("-")]
        in_place = head in ("sed", "perl") and any(a.startswith(("-i", "--in-place")) or a == "-pi" for a in toks[1:])
        code = inline_code(toks)
        if (head in WRITERS or in_place) and any(protected_file(a, gates) for a in args):
            return True
        if code and any(protected_file(w, gates) for w in re.findall(r"[\w./~-]+", code)):
            return True
    return False


BYPASS_NOTE = (" Permissions are bypassed in this session, so it can't be approved here: explain it to the user, who "
               "can run it themselves or approve it in a normal permission mode.")


def decide(out, decision, reason, mode=None):
    """Emit a PreToolUse decision. With permissions bypassed, Claude Code may skip an "ask" (observed for Edit), so
    an ask becomes a deny there."""
    if decision == "ask" and mode == "bypassPermissions":
        decision, reason = "deny", reason + BYPASS_NOTE
    json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                      "permissionDecisionReason": reason}}, out)


def profile_guard(data):
    """Hand the call to a profile's own guard (.claude/goodbehavior/profiles/**/guard.py) when one is installed.
    True when one handled it. Loading or running it must never fail open: any error denies."""
    root = os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or ""
    found = sorted(glob.glob(os.path.join(root, ".claude", "goodbehavior", "profiles", "**", "guard.py"),
                             recursive=True)) if root else []
    if not found:
        return False
    try:
        spec = importlib.util.spec_from_file_location("profile_guard", found[0])
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.decide(data)
    except Exception as exc:  # noqa: BLE001 — fail closed
        result = ("deny", "GoodBehavior guard: the profile guard failed to load (%s: %s), so this could not "
                  "be checked." % (type(exc).__name__, exc))
    if result:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": result[0],
                                          "permissionDecisionReason": result[1]}}, sys.stdout)
    return True


def guard(data):
    """PreToolUse. Deny anything that would print a secret into the conversation. Ask before any command that
    changes things, including changes hidden inside a make target, a script or inline code. Harmless runs."""
    gates = load_gates(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or "")
    if not gates:
        return
    tool = (data.get("tool_name") or "").lower()
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    secrets = gates.get("secrets", {})
    ask = lambda reason: decide(sys.stdout, "ask", reason, data.get("permission_mode"))  # noqa: E731

    if tool in ("edit", "write", "multiedit", "notebookedit"):
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if path and protected_file(path, gates):
            ask("GoodBehavior guard: this edits the guard's own hooks, settings or rules. "
                   "Approve only if Claude has explained what it is changing and why.")
        return
    if tool in ("read", "grep", "notebookread"):
        path = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or "")
        if path and secret_file(path, gates):
            decide(sys.stdout, "deny", "GoodBehavior guard: this is a secret file. Reading it would put the secret "
                   "in the conversation. Change it without reading it (append or replace a line from the shell), "
                   "or ask the user to look.")
        return
    if tool != "bash":
        return
    cmd = str(tool_input.get("command") or "")
    if not cmd:
        return

    if reads_secret_file(cmd, gates) or any(m.search(cmd) for m in secrets.get("match", [])):
        decide(sys.stdout, "deny", "GoodBehavior guard: this would print a secret into the conversation. Use the "
               "value without printing it, or ask the user to run it themselves.")
        return

    if writes_protected_file(cmd, gates):
        ask("GoodBehavior guard: this changes the guard's own hooks, settings or rules. "
               "Approve only if Claude has explained what it is changing and why.")
        return

    hits = [(w, l) for w, l, _ in expanded_lines(cmd, cwd) if changes_things(l, gates)]
    hidden = [(w, l) for w, l, _ in expanded_lines(cmd, cwd)[1:]
              if any(m.search(l) for m in secrets.get("match", [])) or reads_secret_file(l, gates)]
    if not hits and not hidden:
        return  # assessed: nothing in it changes infrastructure or reveals a secret, so it runs
    shown = "; ".join(f"{w}: {l[:90]}" for w, l in (hits + hidden)[:3])
    ask("GoodBehavior guard: this can change live systems or touch secrets, and that may not "
           f"be undoable. Found: {shown}. Approve only if Claude has already explained, in plain words, why it "
           "needs to run, what could break, and how to undo it.")


def is_observe_tool(name):
    return name in OBSERVE_TOOLS or any(h in name for h in OBSERVE_NAME_HINTS)


def observed_after_last_mutation(tools):
    """Was anything run/fetched/driven AFTER the last file mutation this turn?

    A turn with no file mutations armed the gate via bash alone — it executed something, which is
    itself an observation, so it passes."""
    last_mutation = -1
    for i, (name, _) in enumerate(tools):
        if name in MUTATION_TOOLS:
            last_mutation = i
    if last_mutation == -1:
        return True
    return any(is_observe_tool(name) for name, _ in tools[last_mutation + 1:])


def doc_only_mutations(tools):
    """True if every file mutation this turn touched only prose/doc files (and at least one did)."""
    paths = []
    for name, tool_input in tools:
        if name not in MUTATION_TOOLS:
            continue
        p = ""
        if isinstance(tool_input, dict):
            p = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or ""
        paths.append(str(p).lower())
    if not paths:
        return False
    return all(p.endswith(DOC_EXTENSIONS) for p in paths)


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


def turn_tool_uses(entries):
    """All (tool_name, tool_input) the assistant used since the last human message, in order."""
    last_human = -1
    for i, e in enumerate(entries):
        if is_human_turn(e):
            last_human = i
    out = []
    for e in entries[last_human + 1:]:
        if entry_role(e) != "assistant":
            continue
        content = e.get("message", e).get("content", "")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    out.append(((b.get("name") or "").lower(), b.get("input") or {}))
    return out


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
