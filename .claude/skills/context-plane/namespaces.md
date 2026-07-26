# Context Plane namespaces, auth, and write rules

Read this only when the quick map in `SKILL.md` isn't enough (e.g. search isn't surfacing what
you need, or you're about to write). Keep it out of context otherwise.

_Mirrors `dev/skills/context-plane/namespaces` in the plane, with kensa-agent's key and grants._

## Endpoint and auth

- **MCP:** `POST https://www.hanalyx.com/mcp` (JSON-RPC 2.0). Tools: `context_search`,
  `context_get`, `context_write`. `initialize`/`tools/list` need no key; `tools/call` needs one.
- **REST:** `GET /api/context?path=…`, `POST /api/context` `{path, content, baseVersion?}`,
  `GET /api/context/search?q=…`, `POST /api/context/ingest` `{files:[…]}` (≤100, bulk).
- **Key:** `$HANALYX_KENSA_CONTEXT_KEY` (already set in the environment).

  ```bash
  curl -s "https://www.hanalyx.com/api/context?path=shared/KENSA_VISION" \
    -H "Authorization: Bearer $HANALYX_KENSA_CONTEXT_KEY"
  ```

  The key carries kensa-agent's identity and grants; every read/write is logged. Never share it,
  never commit it, and **never use `$HANALYX_PLATFORM_CONTEXT_KEY` or
  `$HANALYX_OPENWATCH_CONTEXT_KEY`**. They are in the same environment, and borrowing one puts a
  false author in the audit trail.

## Namespaces

| Prefix | Holds | kensa-agent access |
|---|---|---|
| `shared/` | Org docs, marketing, moat, product/service descriptions, roadmap, vision, mission, strategy | read + write |
| `dev/` | Coding, git, security, skills, tools, collaboration practices | read + write |
| `projects/kensa/` | Kensa architecture, ADRs, designs, runbooks | read + write (owned) |
| `projects/openwatch/` · `projects/specter/` · `projects/hanalyx-platform/` | Other products | read only |
| `projects/cp/` | The Context Plane's own docs | **403: no grant as of 2026-07-25** |
| `features/` · `bugs/` | CP feature requests / bug reports, prefixed HP / OW / KN / SP | read + write |
| `restricted/` | Finance, HR, legal | 403 by design; never attempt |

## Discovery limits (as of 2026-07)

- **No namespace listing for agent keys**, and `context_search` returns at most ~8 ranked hits.
  A document added outside the write path may not surface, and the index has been observed
  lagging a write by minutes. Search several phrasings before concluding a doc doesn't exist:
  an empty result is not proof of absence, and never proof of no access.
- A `context_get` on a path that doesn't exist returns 404 and **logs a gap** for the owner; a
  path you lack a grant for returns 403 and **logs a denial**. Don't probe speculatively.

## Writing

- Writes are **version-only with optimistic concurrency**: omit `baseVersion` to create; set it to
  the version you last read to update. A stale base is rejected 409. Re-read, reapply, and retry.
- The server injects a 77-byte provenance frontmatter block
  (`last_modified_by` / `source` / `last_verified`) on every write, so a stored document is never
  byte-identical to its local source. Strip that block before any sha256 parity check.
- Paths are extensionless and must live under a folder, not at the org root.
- Follow `dev/DOC_CLASSIFICATION_SCHEMA` when adding docs: manifest-before-ingest, set
  `visibility`, never hand-set freshness, duplicates get a `canonical` pointer rather than a fork.

## Orientation docs to fetch when needed

- `projects/hanalyx-platform/cp/CONTEXT_PLANE_GUIDE`: full operator and agent guide. (The shared
  namespaces reference cites `projects/cp/CONTEXT_PLANE_GUIDE`; that path 403s for kensa-agent.)
- `dev/DOC_CLASSIFICATION_SCHEMA`: how docs are classified and ingested.
- `dev/CP_OWNERSHIP_AND_FRESHNESS`: who keeps which namespace true.
- `projects/kensa/DOC_INVENTORY`: Kensa's own manifest of what is in the plane and what isn't.
