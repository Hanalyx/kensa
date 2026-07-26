---
name: context-plane
description: >
  Fetch Hanalyx organizational knowledge on demand from the Context Plane instead of reading repo
  files. Use when you need shared/company knowledge (mission, roadmap, strategy, moat,
  positioning, brand), a shared standard (git/doc/security/collaboration practices, the doc
  classification schema), or another product's context (OpenWatch, Specter, the platform, the CP
  itself) that isn't already in the file you're working on.
---

# Context Plane: on-demand knowledge

Hanalyx's shared knowledge lives in the **Context Plane (CP)**, a governed store, canonical for
`shared/` and `dev/` knowledge and for every product's `projects/<name>/` docs. **Fetch the one
document you need; never bulk-read a namespace or the repo's `docs/` tree to answer an
org-knowledge question.**

_Canonical copy: `dev/skills/context-plane/SKILL` in the plane. This is the kensa-agent install:
it differs only in the key env var and the orientation path below. Re-sync it if the CP copy
changes._

## When to use this

- Company/org knowledge: mission, roadmap, strategy, moat, competitive positioning, brand.
- A shared standard: git/doc/security/collaboration practices, `dev/DOC_CLASSIFICATION_SCHEMA`.
- Another product's context you don't own.

If the fact is already in the file you're editing, use it directly rather than calling the CP. Kensa's own
working documents live in `docs/` in this repo; read those directly rather than round-tripping
through the plane (see CLAUDE.md § Context Plane).

## How to fetch: one document at a time

1. **Search** for the topic to find candidate paths:
   `context_search("openwatch pricing tiers")`
2. **Get** only the single path you need, then use it and move on:
   `context_get("shared/HANALYX_18_MONTH_STRATEGY")`

Prefer the MCP tools (`mcp__hanalyx-prod__context_search` / `context_get`). If they aren't
available, use `curl` with **`$HANALYX_KENSA_CONTEXT_KEY`**. See `namespaces.md` for endpoints.

Never call `context_get` in a loop to pull a whole folder. Search → fetch the one doc → stop.

## Namespace map (quick)

`shared/` org & market · `dev/` standards & skills · `projects/<name>/` one product
(`kensa`, `openwatch`, `specter`, `hanalyx-platform`) · `features/` + `bugs/` CP requests.

Full catalog, auth details, and write rules are in `namespaces.md`. **Read that only if search
isn't finding what you need**, so it stays out of context otherwise.

## Rules

- Read before you write; write only `projects/kensa/`, `shared/`, `dev/`, `features/`, `bugs/`
  (the grants kensa-agent holds as of 2026-07-25).
- The CP is canonical for `shared/` + `dev/` knowledge; repo copies are authoring mirrors.
- **Kensa owns `projects/kensa/` freshness**: a standing duty, not a one-time ingest. See
  `dev/CP_OWNERSHIP_AND_FRESHNESS`.
- Don't edit another project's namespace. File a `bugs/` or `features/` entry instead, prefixed
  `HP` / `OW` / `KN` / `SP`.
- Hit a CP limitation? File it under `features/` or `bugs/`.
