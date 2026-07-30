#!/usr/bin/env python3
"""Hanalyx documentation style check (language-neutral: runs anywhere python3 is present).

Enforces the prohibited list from the developer documentation style guide (canonical copy:
Context Plane dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE):

  1. Em dashes (the U+2014 character).            markdown prose
  2. AI-speak filler and hype words and phrases.  markdown prose
  3. Emojis / decorative pictographs.             markdown AND structured files

Scope (HP-008). Em dashes and AI-speak are prose rules and run on Markdown only. The emoji rule is
not a prose rule, so it also runs on structured files (.yml, .yaml, .json), where emoji in issue
templates and workflows are otherwise invisible to the gate.

Matching (HP-003).
- Single always-hype words match their inflected forms (leverage / leverages / leveraging /
  streamlined), so the common half of AI speak no longer escapes the check.
- Words that also have a legitimate technical sense (harness, unlock, elevate, delve, embark)
  are matched only inside their hype phrase, never as a bare word, so "test harness",
  "unlock_time", and "elevated privileges" are not flagged.
- Fenced code blocks and inline `code` spans in Markdown are exempt (code is not prose).
- A line with `<!-- doc-style: allow -->` is skipped when a maintainer has cleared the term.

Usage:
  python3 scripts/check-doc-style.py <file> [more ...]   # check specific files
  python3 scripts/check-doc-style.py --changed           # files changed vs origin/main
  python3 scripts/check-doc-style.py --all               # all tracked files
  python3 scripts/check-doc-style.py --version           # print version and self sha256
  python3 scripts/check-doc-style.py --selftest          # run built-in matching tests
"""
import hashlib
import re
import subprocess
import sys

VERSION = "2"

# Single always-hype words, matched with their inflected forms (verbs and adjectives).
HYPE_WORDS = [
    "leverage", "utilize", "facilitate", "empower", "supercharge", "streamline",
    "seamless", "robust", "powerful", "revolutionary",
]

# Multiword and hyphenated hype terms, filler openers, model tells, and the hype PHRASES for the
# words that also have a legitimate technical sense (harness, unlock, elevate, delve, embark).
# Matched as substrings, case-insensitively.
HYPE_PHRASES = [
    "cutting-edge", "best-in-class", "world-class", "state-of-the-art",
    "game-changing", "game-changer", "game changer", "next-generation", "next generation",
    "enterprise-grade", "blazing-fast", "blazing fast",
    "needless to say", "at the end of the day", "in today's fast-paced world",
    "in the ever-evolving", "rest assured", "peace of mind", "dive in",
    "in conclusion", "as an ai", "great question", "certainly!",
    "you're all set", "you are all set", "we've got you covered", "we have got you covered",
    "harness the", "harnessing the", "harnesses the",
    "elevate your", "elevates your",
    "unlock the potential", "unlock the power", "unlocks the potential",
    "delve into", "embark on",
]

# Contraction pairs written once as a regex. The guide tells writers to use contractions, so the
# uncontracted form is the one that slips through when only the contracted form is listed.
CONTRACTION_RES = [
    re.compile(r"it(?:'s| is) important to note", re.I),
    re.compile(r"it(?:'s| is) worth mentioning", re.I),
]


def word_re(w):
    """Match a hype word and its common inflections, handling a silent trailing e."""
    if w.endswith("e"):
        return re.compile(rf"\b{re.escape(w[:-1])}(?:e|es|ed|ing)\b", re.I)
    return re.compile(rf"\b{re.escape(w)}(?:s|es|ed|ing|ly)?\b", re.I)


WORD_RES = [(w, word_re(w)) for w in HYPE_WORDS]
PHRASE_RES = [(p, re.compile(re.escape(p), re.I)) for p in HYPE_PHRASES]

EM_DASH = re.compile("—")
EMOJI = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002B00-\U00002BFF"
    "\U0001F1E6-\U0001F1FF\U0000FE00-\U0000FE0F]"
)
INLINE_CODE = re.compile(r"`[^`]*`")
FENCE = re.compile(r"^\s*```")
ALLOW = re.compile(r"<!--\s*doc-style:\s*allow\s*-->")

PROSE_EXT = (".md",)
EMOJI_EXT = (".md", ".yml", ".yaml", ".json")
GLOBS = ["*.md", "*.yml", "*.yaml", "*.json"]


def git(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
    except Exception:
        return ""


def resolve_files(argv):
    flags = {a for a in argv if a.startswith("--")}
    explicit = [a for a in argv if not a.startswith("--")]
    if explicit:
        return explicit
    if "--all" in flags:
        out = []
        for g in GLOBS:
            out += [f for f in git(["git", "ls-files", g]).splitlines() if f]
        return out
    base = git(["git", "merge-base", "origin/main", "HEAD"]) or "origin/main"
    changed = git(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD", "--"] + GLOBS)
    if not changed:
        changed = git(["git", "diff", "--name-only", "--cached", "--"] + GLOBS)
    return [f for f in changed.splitlines() if f]


def line_findings(raw, is_prose, do_emoji, in_fence):
    """Return (list of (label, token), new_in_fence) for one line. Reports every match, not just
    the first, so a heavily affected line can be cleaned in one pass."""
    if is_prose and FENCE.match(raw):
        return [], (not in_fence)
    if in_fence or ALLOW.search(raw):
        return [], in_fence
    out = []
    if do_emoji:
        m = EMOJI.search(raw)
        if m:
            out.append(("emoji", m.group(0)))
    if is_prose:
        line = INLINE_CODE.sub("", raw)
        if EM_DASH.search(line):
            out.append(("em-dash", "—"))
        for _term, rx in WORD_RES + PHRASE_RES:
            mm = rx.search(line)
            if mm:
                out.append(("ai-speak", mm.group(0)))
        for rx in CONTRACTION_RES:
            mm = rx.search(line)
            if mm:
                out.append(("ai-speak", mm.group(0)))
    return out, in_fence


def check_file(path, report):
    is_prose = path.endswith(PROSE_EXT)
    do_emoji = path.endswith(EMOJI_EXT)
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return 0
    findings = 0
    in_fence = False
    for n, raw in enumerate(lines, 1):
        hits, in_fence = line_findings(raw, is_prose, do_emoji, in_fence)
        for label, token in hits:
            report(path, n, label, token)
            findings += 1
    return findings


def selftest():
    """Positive and negative cases. Returns the number of failures."""
    must_flag = [
        "OpenWatch leverages Kensa for remediation.",
        "The team is leveraging the queue.",
        "It utilizes PostgreSQL.",
        "Kensa empowers operators.",
        "A streamlined workflow.",
        "This streamlines onboarding.",
        "It facilitates rollback.",
        "It is worth mentioning that scans are queued.",
        "You are all set.",
        "We have got you covered.",
        "Great question.",
        "Certainly! Here is the command.",
        "harness the power of X.",
        "unlock the potential of the fleet.",
        "A seamless, robust, powerful platform.",
    ]
    must_pass = [
        "The test harness runs nightly.",
        "Unlock the account.",
        "Run with elevated privileges.",
        "Set unlock_time in the config.",
        "We foster adoption across teams.",
        "The scheduler embarked and returned.",
        "It reads the value and returns it.",
    ]
    fails = 0
    for text in must_flag:
        hits, _ = line_findings(text, True, True, False)
        if not hits:
            sys.stderr.write(f"  selftest: expected a finding, got none: {text!r}\n")
            fails += 1
    for text in must_pass:
        hits, _ = line_findings(text, True, True, False)
        if hits:
            sys.stderr.write(f"  selftest: expected clean, got {hits}: {text!r}\n")
            fails += 1
    hits, _ = line_findings('  title: "Bug report \U0001F41B"', is_prose=False, do_emoji=True, in_fence=False)
    if not any(l == "emoji" for l, _ in hits):
        sys.stderr.write("  selftest: emoji not caught in a structured (.yml) line\n")
        fails += 1
    if fails:
        sys.stderr.write(f"\ndoc-style selftest FAILED: {fails} case(s).\n")
    else:
        print("doc-style selftest: all cases pass")
    return fails


def main():
    argv = sys.argv[1:]
    if "--version" in argv:
        h = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
        print(f"doc-style check version {VERSION}  sha256 {h}")
        return 0
    if "--selftest" in argv:
        return 1 if selftest() else 0

    files = resolve_files(argv)
    checkable = [f for f in files if f.endswith(EMOJI_EXT)]
    if not checkable:
        print("doc-style: nothing to check")
        return 0

    findings = 0

    def report(path, n, label, token):
        sys.stderr.write(f"  {path}:{n}  {label}: {token!r}\n")

    for path in checkable:
        findings += check_file(path, report)

    if findings:
        sys.stderr.write(
            f"\ndoc-style FAILED: {findings} finding(s). "
            "See dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE.\n"
            "Fix the prose, or add `<!-- doc-style: allow -->` to a line a maintainer has cleared.\n"
        )
        return 1
    print(f"doc-style: {len(checkable)} file(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
