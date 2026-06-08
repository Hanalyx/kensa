# Scan And Remediate

**Stub.** The bulk of this chapter is forthcoming. Until it lands, the
authoritative source for the topics not yet covered below is:

- The relevant binary's `--help` output
- The `.spec.yaml` file(s) under `specs/` for the components
  involved
- The atomicity contract guarantees described in
  [`README.md`](../../README.md) and
  [`03-concepts.md`](03-concepts.md)

The one part that IS documented here is the live progress stream.

---

## Live progress (`--progress`)

`kensa check`, `kensa detect`, and `kensa remediate` can show a live
progress stream while they run — per-rule check results, per-probe
results, and per-phase transaction updates — so you can watch a long
scan or remediation advance instead of waiting for the final result.

### The flag

```
--progress=auto|always|never    (default: auto)
```

| Mode     | Behavior |
|----------|----------|
| `auto`   | Progress is shown only when **stderr is a terminal** and `--quiet` is not set. Redirect stderr to a file or a pipe (CI, logs) and it stays silent. This is the default. |
| `always` | Force the stream on regardless of the terminal heuristic — useful to capture it in a redirected stderr. |
| `never`  | Force the stream off regardless of the terminal. |

`--quiet` wins over `auto`: `--progress=auto --quiet` is silent. (Use
`--progress=always` if you want progress *and* a quiet final result.)
`--verbose` is unrelated — it controls detail in the final **result**,
not the live stream.

An unrecognized value (anything other than `auto`, `always`, `never`) is
a usage error (exit 2), reported before any SSH connection is attempted.

### Where it goes: stderr, never stdout

**All progress bytes go to stderr. stdout carries only the canonical
result.** This separation is absolute and is what makes the feature safe
to script around:

```bash
# The progress stream is on the terminal (stderr); the JSON result is
# captured cleanly from stdout with nothing interleaved.
kensa check web01 --progress=always -o json > result.json
```

Because the result lives on a different stream, turning progress on or
off **never changes** the bytes written to stdout, the exit code, or any
`-o FILE` serialization. The same run produces byte-identical stdout
with `--progress=never` and `--progress=always`.

### Progress is cosmetic and lossy; the result is authoritative

Treat the live stream as a convenience, not a record:

- It is **cosmetic** — a display aid. Never parse it as the source of
  truth for what happened.
- It is **lossy** for `remediate`. The remediation runs through the
  transaction engine, whose event bus has a bounded per-subscriber
  buffer and **drops** events rather than slowing the engine's hot path.
  Under a fast burst some per-phase or per-completion lines may not be
  rendered.
- The **result struct is authoritative.** The final summary, the exit
  code, and every `-o FORMAT[:PATH]` output are produced from the
  canonical `ScanResult` / `RemediationResult`, never reconstructed from
  the rendered stream. If a progress line is dropped, the result is
  still complete and correct.

To make the lossiness visible rather than silent, `kensa remediate`
prints one advisory line on stderr when the stream rendered fewer
transaction-completion events than the authoritative result reports:

```
kensa: 2 transaction-completion event(s) dropped from the progress stream (cosmetic; the result above is authoritative)
```

That line is advisory only — it changes nothing about the result on
stdout, the exit code, or any `-o FILE` output. Seeing it does not mean a
remediation step was missed; it means a *display* line was. Always read
the result (or `-o json`/`oscal`/etc.) for the record of what changed.

### Terminal vs. piped rendering

On an interactive terminal (`auto` with a TTY, or `always` on a TTY),
the single-host `check`/`detect`/`remediate` paths render transient
per-rule and per-phase lines **in place** — each overwrites the previous
one so the terminal does not scroll — while milestone lines (scan start,
transaction started/done, scan end) stay on screen.

When stderr is **not** a terminal (piped, redirected, CI) — or in
multi-host inventory mode, where collapsing many hosts onto one line
would be unreadable — progress renders as **plain lines**, one per
update, newline-terminated, with no carriage-return rewrites or escape
sequences. This keeps captured logs clean and stable.

### Inventory (multi-host)

`kensa check`/`detect` against an `--inventory` show a single merged
stream with each line prefixed by its host address, so you can follow a
fleet scan on one terminal. stdout still carries the concatenated
per-host result documents. (`remediate` and `rollback` are single-host;
they require `--host`.)
