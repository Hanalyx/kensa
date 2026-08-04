#!/usr/bin/env python3
"""Hanalyx documentation style check (language-neutral: runs anywhere python3 is present).

Enforces the prohibited list from the developer documentation style guide (canonical copy:
Context Plane dev/DEVELOPER_DOCUMENTATION_STYLE_GUIDE):

  1. Em dashes (the U+2014 character).            markdown prose
  2. AI-speak filler and hype words and phrases.  markdown prose
  3. Emojis / decorative pictographs.             markdown AND structured files
  4. British spellings (US English rule).         markdown prose, per line
  5. Reading level above the gate.                markdown prose, per FILE

Reading level (v3) is Flesch-Kincaid, scored per file over prose only: fenced code, inline code,
tables, headings, URLs and link targets are removed first, so a term of art never raises the
grade. The style guide is explicit that the target constrains sentence construction, not
vocabulary. Files under FK_MIN_SENTENCES are not scored, and READABILITY_EXEMPT is a ratcheting
ledger that may only shrink.

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

VERSION = "3"

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


# British -> US spellings (style guide: "US English"). Key is the British form; value is the US
# form used in the message. Matched case-insensitively on word boundaries, in prose only, with
# inline code, fenced blocks, URLs and link targets already stripped -- so an identifier like
# `unlock_time` or a URL containing /organisation/ is never flagged.
#
# Deliberately NOT listed: pairs where the British form is also a valid US word with a different
# meaning. "licence"/"license" and "practise"/"practice" are noun/verb splits in British usage and
# a blanket rule would produce wrong advice, so they are left to the writer.
BRITISH = {
    "behaviour": "behavior", "behaviours": "behaviors", "behavioural": "behavioral",
    "colour": "color", "colours": "colors", "coloured": "colored",
    "favour": "favor", "favours": "favors", "favoured": "favored", "favourite": "favorite",
    "honour": "honor", "honours": "honors", "labour": "labor",
    "centre": "center", "centres": "centers", "centred": "centered",
    "defence": "defense", "offence": "offense",
    "judgement": "judgment", "acknowledgement": "acknowledgment",
    "analyse": "analyze", "analysed": "analyzed", "analyses": "analyzes", "analysing": "analyzing",
    "catalogue": "catalog", "catalogues": "catalogs", "dialogue": "dialog",
    "summarise": "summarize", "summarised": "summarized", "summarising": "summarizing",
    "generalise": "generalize", "generalised": "generalized", "generalisable": "generalizable",
    "recognise": "recognize", "recognised": "recognized", "recognising": "recognizing",
    "organise": "organize", "organised": "organized", "organisation": "organization",
    "organisations": "organizations", "organisational": "organizational",
    "normalise": "normalize", "normalised": "normalized", "normalisation": "normalization",
    "prioritise": "prioritize", "prioritised": "prioritized",
    "minimise": "minimize", "minimised": "minimized", "maximise": "maximize",
    "initialise": "initialize", "initialised": "initialized", "initialisation": "initialization",
    "serialise": "serialize", "serialised": "serialized", "serialisation": "serialization",
    "synchronise": "synchronize", "synchronised": "synchronized",
    "authorise": "authorize", "authorised": "authorized", "authorisation": "authorization",
    "customise": "customize", "customised": "customized",
    "modelled": "modeled", "modelling": "modeling",
    "cancelled": "canceled", "cancelling": "canceling",
    "labelled": "labeled", "labelling": "labeling",
    "signalled": "signaled", "travelled": "traveled", "fuelled": "fueled",
    "whilst": "while", "amongst": "among",
}
SPELLING_RES = [(b, u, re.compile(rf"\b{b}\b", re.I)) for b, u in BRITISH.items()]

# Readability (style guide: "Reading level"). Flesch-Kincaid grade level, computed per FILE over
# prose only. Enforcement notes, because a naive readability gate on technical docs is worse than
# no gate:
#
#   * Terms of art must not be penalized. The guide is explicit that the target constrains
#     sentence construction, not vocabulary, so code spans, fenced blocks, tables, headings, URLs
#     and link targets are all removed before scoring. What is left is the sentences a reader
#     actually reads.
#   * Short files are not scored. A file with a handful of sentences produces a grade dominated by
#     one long line, which is noise, not signal.
#   * The threshold is deliberately looser than the 10 the guide asks for. 10 is the writing
#     target; this is the point where a document is hard enough to be worth a second pass. Gating
#     exactly at the target would fail prose that is merely dense rather than unclear.
# FK_GATE was set by measuring the corpus, not by picking a round number. Across 23 scorable
# tracked documents the median grade is 9.2 and the mean 9.6, and nothing exceeds 12.6. A gate at
# 14 would therefore have failed nothing at all: a green check that proves the check ran, not that
# the prose is readable. This repo has shipped that failure before (a deadman timer dead since
# v0.1.0 behind a green suite), so the gate is set where it actually bites.
FK_TARGET = 10.0          # what the guide asks a writer to aim for
FK_GATE = 12.0            # where the build fails: ~3 grades above target, 2 files over it today
FK_MIN_SENTENCES = 25     # below this, one long sentence dominates and the score is noise

# Files exempt from the readability gate, each with a reason. Ratcheting: this list may shrink,
# never grow, and it is the same debt-ledger pattern as every other gate in this repo. An entry is
# cleared by rewriting the prose, never by raising FK_GATE.
READABILITY_EXEMPT = {
    "CHANGELOG.md": "release notes for shipped versions are a historical record; entries are "
                    "not rewritten for style after a tag (grade 12.1)",
    "BACKLOG.md": "pre-existing at gate adoption, grade 12.6; drain by rewriting, not by "
                  "raising the gate",
    "docs/guide/07-integration.md": "pre-existing at gate adoption, grade 12.1; public operator "
                                    "manual, so a rewrite needs re-verification against the "
                                    "binary before it lands",
}

MD_TABLE = re.compile(r"^\s*\|")
MD_HEADING = re.compile(r"^\s*#{1,6}\s")
MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
BARE_URL = re.compile(r"https?://\S+")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
FRONTMATTER = re.compile(r"\A---\n.*?\n---\n", re.S)
LIST_MARK = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


def prose_blocks(text):
    """Yield the prose blocks of a Markdown document, with everything a reader does not read as a
    sentence removed: frontmatter, fenced code, inline code, tables, headings, link targets, URLs.

    Returns a list of blocks. A block is a paragraph or a single list item, which matters because
    list items usually have no terminal punctuation and would otherwise fuse into one enormous
    sentence and wreck the average."""
    text = FRONTMATTER.sub("", text)
    text = HTML_COMMENT.sub("", text)
    out, in_fence = [], False
    for raw in text.split("\n"):
        if FENCE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence or MD_TABLE.match(raw) or MD_HEADING.match(raw):
            continue
        line = INLINE_CODE.sub(" ", raw)
        line = MD_LINK.sub(r"\1", line)
        line = BARE_URL.sub(" ", line)
        is_item = bool(LIST_MARK.match(line))
        line = LIST_MARK.sub("", line).strip()
        if not line:
            out.append(None)          # paragraph break
        elif is_item:
            out.append(None)
            out.append(line)
        else:
            out.append(line)
    blocks, cur = [], []
    for piece in out + [None]:
        if piece is None:
            if cur:
                blocks.append(" ".join(cur))
                cur = []
        else:
            cur.append(piece)
    return blocks


def syllables(word):
    """Approximate syllable count. Standard vowel-group heuristic; good enough for an average
    over hundreds of words, which is all Flesch-Kincaid needs."""
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    groups = re.findall(r"[aeiouy]+", w)
    n = len(groups)
    if w.endswith("e") and not w.endswith(("le", "ee", "ye")) and n > 1:
        n -= 1
    return max(n, 1)


def fk_grade(text):
    """Return (grade, sentences, words) using Flesch-Kincaid. A block with no terminal punctuation
    counts as one sentence rather than being merged into the next."""
    sents, words, syls = 0, 0, 0
    for block in prose_blocks(text):
        parts = [p for p in SENT_SPLIT.split(block) if p.strip()]
        for p in parts:
            toks = re.findall(r"[A-Za-z][A-Za-z'-]*", p)
            if not toks:
                continue
            sents += 1
            words += len(toks)
            syls += sum(syllables(t) for t in toks)
    if sents == 0 or words == 0:
        return None, sents, words
    grade = 0.39 * (words / sents) + 11.8 * (syls / words) - 15.59
    return round(grade, 1), sents, words


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
        # Spelling runs on prose with link targets and URLs removed, so a path segment or a
        # third-party URL that happens to contain a British spelling is not a finding.
        spell_line = BARE_URL.sub(" ", MD_LINK.sub(r"\1", line))
        for _brit, us, rx in SPELLING_RES:
            mm = rx.search(spell_line)
            if mm:
                out.append(("us-spelling", f"{mm.group(0)} -> {us}"))
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
    if is_prose and path not in READABILITY_EXEMPT:
        grade, sents, _words = fk_grade("\n".join(lines))
        if grade is not None and sents >= FK_MIN_SENTENCES and grade > FK_GATE:
            report(path, 0, "reading-level",
                   f"Flesch-Kincaid grade {grade} over {sents} sentences "
                   f"(gate {FK_GATE}, target {FK_TARGET}); shorten the long sentences")
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
        "The behaviour is documented.",
        "We summarise the findings.",
        "Run whilst the scan is active.",
    ]
    must_pass = [
        "The test harness runs nightly.",
        "Unlock the account.",
        "Run with elevated privileges.",
        "Set unlock_time in the config.",
        "We foster adoption across teams.",
        "The scheduler embarked and returned.",
        "It reads the value and returns it.",
        "The behavior is documented.",
        "See https://example.com/organisation/x for details.",
        "Set `initialise_on_boot` in the config.",
        "The license file is at the repo root.",
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
