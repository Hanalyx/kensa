#!/usr/bin/env python3
"""Interactive review server for Kensa coverage report.

Lightweight Flask server that serves the coverage report with per-rule
detail pages and an inline review workflow. Reviews are persisted to
SQLite (reports/review.db).

Usage:
    python3 scripts/review_server.py                  # http://127.0.0.1:5050
    python3 scripts/review_server.py --port 8080
    python3 scripts/review_server.py --host 0.0.0.0

Requires: pip install flask
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from flask import Flask, abort, jsonify, redirect, request, url_for
except ImportError:
    if __name__ == "__main__":
        print(
            "Flask is required for the review server.\n"
            "Install it with: pip install flask",
            file=sys.stderr,
        )
        sys.exit(1)
    raise

import yaml

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from scripts.coverage_report import (  # noqa: E402
    compute_data,
    load_control_titles,
    load_history,
    load_mappings,
    load_rules,
    open_db,
    render_html,
)

REVIEW_DB = ROOT / "reports" / "review.db"
REVIEW_YAML = ROOT / "reports" / "review.yaml"

VALID_FLAGS = [
    "wrong-mapping",
    "incorrect-check",
    "incorrect-remediation",
    "verify",
    "stale-reference",
    "missing-coverage",
    "need-pr",
    "cleared",
]

FLAG_COLORS = {
    "wrong-mapping": "#7c3aed",
    "incorrect-check": "#dc2626",
    "incorrect-remediation": "#e11d48",
    "verify": "#ca8a04",
    "stale-reference": "#ea580c",
    "missing-coverage": "#3b82f6",
    "need-pr": "#f97316",
    "cleared": "#16a34a",
}


# ── SQLite layer ──────────────────────────────────────────────────────────────


def open_review_db(path: Path | None = None) -> sqlite3.Connection:
    """Open or create the review database."""
    p = path or REVIEW_DB
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS reviews (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id   TEXT    NOT NULL,
            date      TEXT    NOT NULL,
            reviewer  TEXT    NOT NULL,
            flag      TEXT    NOT NULL,
            note      TEXT    NOT NULL DEFAULT ''
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_rule_id ON reviews(rule_id)")
    conn.commit()
    return conn


def add_review(
    conn: sqlite3.Connection,
    rule_id: str,
    reviewer: str,
    flag: str,
    note: str = "",
    date_str: str | None = None,
) -> dict:
    """Insert a review entry and return the created row as a dict."""
    d = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cur = conn.execute(
        "INSERT INTO reviews (rule_id, date, reviewer, flag, note) VALUES (?,?,?,?,?)",
        (rule_id, d, reviewer, flag, note),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM reviews WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


def get_rule_reviews(conn: sqlite3.Connection, rule_id: str) -> list[dict]:
    """Get all review entries for a rule, sorted chronologically."""
    rows = conn.execute(
        "SELECT * FROM reviews WHERE rule_id=? ORDER BY date ASC, id ASC",
        (rule_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_reviews(conn: sqlite3.Connection) -> dict[str, list[dict]]:
    """Get all reviews grouped by rule_id."""
    rows = conn.execute("SELECT * FROM reviews ORDER BY date ASC, id ASC").fetchall()
    result: dict[str, list[dict]] = {}
    for r in rows:
        d = dict(r)
        result.setdefault(d["rule_id"], []).append(d)
    return result


def compute_flag_status(conn: sqlite3.Connection, rule_id: str) -> str | None:
    """Return the active flag type for a rule, or None if cleared/unflagged."""
    row = conn.execute(
        "SELECT flag FROM reviews WHERE rule_id=? ORDER BY date DESC, id DESC LIMIT 1",
        (rule_id,),
    ).fetchone()
    if not row:
        return None
    return None if row["flag"] == "cleared" else row["flag"]


def delete_review(conn: sqlite3.Connection, review_id: int) -> bool:
    """Delete a review entry by id. Returns True if deleted."""
    cur = conn.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    conn.commit()
    return cur.rowcount > 0


def import_from_yaml(conn: sqlite3.Connection, yaml_path: Path | None = None) -> int:
    """Import reviews from YAML sidecar into DB. Returns count imported."""
    p = yaml_path or REVIEW_YAML
    # Skip if DB already has data
    count = conn.execute("SELECT COUNT(*) as c FROM reviews").fetchone()["c"]
    if count > 0:
        return 0
    if not p.exists():
        return 0
    try:
        data = yaml.safe_load(p.read_text())
        if not data or not isinstance(data, dict):
            return 0
        reviews = data.get("reviews", {})
        if not isinstance(reviews, dict):
            return 0
    except Exception:
        return 0

    imported = 0
    for rule_id, entries in reviews.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            conn.execute(
                "INSERT INTO reviews (rule_id, date, reviewer, flag, note) VALUES (?,?,?,?,?)",
                (
                    rule_id,
                    str(entry.get("date", "")),
                    entry.get("reviewer", "unknown"),
                    entry.get("flag", "verify"),
                    entry.get("note", ""),
                ),
            )
            imported += 1
    conn.commit()
    return imported


def get_review_summary(conn: sqlite3.Connection) -> dict:
    """Get summary of flagged rules."""
    all_reviews = get_all_reviews(conn)
    flagged: dict[str, str] = {}
    for rule_id, entries in all_reviews.items():
        if entries:
            last = entries[-1]["flag"]
            if last != "cleared":
                flagged[rule_id] = last
    by_type: dict[str, int] = {}
    for ft in flagged.values():
        by_type[ft] = by_type.get(ft, 0) + 1
    return {"total_flagged": len(flagged), "by_type": by_type}


# ── Flask app ─────────────────────────────────────────────────────────────────


def _rewrite_rule_links(html: str) -> str:
    """Replace onclick modal openers with <a href> links to rule pages."""
    import re

    html = re.sub(
        r"""<a class="rule-link" onclick="showRuleDetail\('([^']+)'\)">""",
        r'<a class="rule-link" href="/rule/\1">',
        html,
    )
    return html


def _render_rule_page(rule: dict, reviews: list[dict], flag_status: str | None) -> str:
    """Render a full HTML page for a single rule."""
    r = rule
    flag_color = FLAG_COLORS.get(flag_status or "", "#94a3b8")

    # References
    refs_html = ""
    refs = r.get("references", {})
    if refs:
        refs_html = (
            '<div class="detail-section"><h3>Framework References</h3><table><tbody>'
        )
        for fw, val in refs.items():
            if isinstance(val, list):
                refs_html += f"<tr><td><strong>{fw}</strong></td><td>{', '.join(str(v) for v in val)}</td></tr>"
            elif isinstance(val, dict):
                for sub, sv in val.items():
                    if isinstance(sv, dict):
                        parts = ", ".join(f"{k}: {v}" for k, v in sv.items())
                    else:
                        parts = str(sv)
                    refs_html += f"<tr><td><strong>{fw} / {sub}</strong></td><td>{parts}</td></tr>"
        refs_html += "</tbody></table></div>"

    # Platforms
    plats_html = ""
    platforms = r.get("platforms", [])
    if platforms:
        plats_html = '<div class="detail-section"><h3>Platforms</h3>'
        for p in platforms:
            parts = [p.get("family", "")]
            if p.get("min_version"):
                parts.append(f"min: {p['min_version']}")
            if p.get("max_version"):
                parts.append(f"max: {p['max_version']}")
            plats_html += f'<div class="meta-item">{" · ".join(parts)}</div>'
        plats_html += "</div>"

    # Implementations
    impls_html = ""
    impls = r.get("implementations", [])
    if impls:
        impls_html = '<div class="detail-section"><h3>Implementations</h3>'
        for i, impl in enumerate(impls):
            gate = ""
            if impl.get("when"):
                gate = f'<code class="gate">when: {impl["when"]}</code>'
            elif impl.get("default"):
                gate = '<code class="gate">default</code>'

            chk = impl.get("check", {})
            chk_html = ""
            if chk.get("method") == "command" and chk.get("run"):
                chk_html = f'<div class="check-info"><strong>Check:</strong> <code>command</code></div><pre>{_esc(chk["run"])}</pre>'
            elif chk.get("checks"):
                chk_html = '<div class="check-info"><strong>Check:</strong> <code>multi_check</code></div>'
                for c in chk["checks"]:
                    parts = [f"<code>{c.get('method', '?')}</code>"]
                    for k in ("name", "path", "key", "expected", "state"):
                        if c.get(k):
                            parts.append(f"{k}={_esc(str(c[k]))}")
                    chk_html += f'<div class="sub-item">{"  ".join(parts)}</div>'
            elif chk.get("method"):
                parts = [f"<strong>Check:</strong> <code>{chk['method']}</code>"]
                for k in (
                    "name",
                    "path",
                    "key",
                    "expected",
                    "state",
                    "parameter",
                    "value",
                ):
                    if chk.get(k):
                        parts.append(f"{k}=<code>{_esc(str(chk[k]))}</code>")
                chk_html = f'<div class="check-info">{" · ".join(parts)}</div>'

            rem = impl.get("remediation", {})
            rem_html = ""
            if rem.get("mechanism"):
                rem_html = f'<div class="rem-info"><strong>Remediation:</strong> <code>{rem["mechanism"]}</code></div>'
                if rem.get("note"):
                    rem_html += f'<div class="rem-note">{_esc(rem["note"])}</div>'
            elif rem.get("steps"):
                rem_html = '<div class="rem-info"><strong>Remediation:</strong> <code>multi_step</code></div>'
                for s in rem["steps"]:
                    sparts = [f"<code>{s.get('mechanism', '?')}</code>"]
                    if s.get("name"):
                        sparts.append(s["name"])
                    if s.get("run"):
                        run_preview = s["run"][:100] + (
                            "…" if len(s["run"]) > 100 else ""
                        )
                        sparts.append(f"run: {_esc(run_preview)}")
                    rem_html += f'<div class="sub-item">{" ".join(sparts)}</div>'

            impls_html += f'<div class="impl-block"><div class="impl-header">Implementation {i + 1} {gate}</div>{chk_html}{rem_html}</div>'
        impls_html += "</div>"

    # Review history
    reviews_html = ""
    if reviews:
        reviews_html = '<div class="detail-section"><h3>Review History</h3>'
        for rv in reviews:
            rc = FLAG_COLORS.get(rv["flag"], "#94a3b8")
            reviews_html += f"""<div class="review-entry" style="border-left-color:{rc}">
                <div class="re-meta">{rv["date"]} · {rv["reviewer"]} · <span style="color:{rc};font-weight:600">{rv["flag"]}</span></div>
                <div class="re-note">{_esc(rv.get("note", ""))}</div>
            </div>"""
        reviews_html += "</div>"

    # Flag options
    flag_options = "\n".join(
        f'<option value="{f}">{f}</option>' for f in VALID_FLAGS if f != "cleared"
    )
    flag_options += '\n<option value="cleared">cleared</option>'

    # Tags
    tags_html = " ".join(f'<span class="tag">{t}</span>' for t in r.get("tags", []))

    flag_badge = ""
    if flag_status:
        flag_badge = f'<span class="flag-badge" style="background:{flag_color};color:#fff">{flag_status}</span>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{r["id"]} — Kensa Rule Review</title>
<style>
:root {{
  --bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;
  --accent:#3b82f6;--green:#16a34a;--red:#dc2626;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}}
header{{background:#1e293b;color:#fff;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}}
header h1{{font-size:18px;font-weight:600}}
header a{{color:#94a3b8;text-decoration:none;font-size:13px}}
header a:hover{{color:#fff}}
main{{max-width:960px;margin:0 auto;padding:24px}}
.breadcrumb{{font-size:13px;color:var(--muted);margin-bottom:16px}}
.breadcrumb a{{color:var(--accent);text-decoration:none}}
.breadcrumb a:hover{{text-decoration:underline}}
.rule-header{{margin-bottom:24px}}
.rule-header h2{{font-size:22px;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.rule-header p{{color:var(--muted);font-size:13px}}
.flag-badge{{display:inline-block;padding:3px 10px;border-radius:9999px;font-size:12px;font-weight:600}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}}
.meta-card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px}}
.meta-card .label{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600;margin-bottom:4px}}
.meta-card .value{{font-size:14px;font-weight:500}}
.tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;background:#eff6ff;color:var(--accent);margin:2px}}
.badge{{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:12px;font-weight:500}}
.badge-high{{background:#fee2e2;color:#dc2626}}
.badge-medium{{background:#fef9c3;color:#ca8a04}}
.badge-low{{background:#dcfce7;color:#16a34a}}
.badge-critical{{background:#fee2e2;color:#dc2626}}
.detail-section{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}}
.detail-section h3{{font-size:14px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
.detail-section p{{font-size:14px;line-height:1.7}}
.detail-section table{{width:100%;border-collapse:collapse;font-size:13px}}
.detail-section td{{padding:6px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
.detail-section td:first-child{{white-space:nowrap;width:180px}}
.impl-block{{background:#f8fafc;border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:10px}}
.impl-header{{font-weight:600;margin-bottom:8px;font-size:14px}}
.gate{{background:#eff6ff;color:var(--accent);padding:2px 6px;border-radius:4px;font-size:12px;margin-left:6px}}
.check-info,.rem-info{{margin-bottom:6px;font-size:13px}}
.rem-note{{font-size:13px;color:var(--muted);margin-left:12px;margin-top:4px}}
.sub-item{{margin-left:16px;font-size:12px;padding:2px 0}}
pre{{margin:8px 0;padding:12px;background:#1e293b;color:#e2e8f0;border-radius:6px;font-size:13px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.5}}
.review-entry{{border-left:3px solid var(--border);padding:10px 14px;margin-bottom:10px;background:#f8fafc;border-radius:0 6px 6px 0}}
.re-meta{{font-size:12px;color:var(--muted);margin-bottom:4px}}
.re-note{{font-size:13px}}
.review-form{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}}
.review-form h3{{font-size:14px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
.form-row{{margin-bottom:12px}}
.form-row label{{display:block;font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}}
.form-row select,.form-row input,.form-row textarea{{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:6px;font-size:13px;font-family:inherit;outline:none}}
.form-row select:focus,.form-row input:focus,.form-row textarea:focus{{border-color:var(--accent);box-shadow:0 0 0 2px #bfdbfe}}
.form-row textarea{{min-height:80px;resize:vertical}}
.btn{{padding:8px 20px;border:none;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer}}
.btn-primary{{background:var(--accent);color:#fff}}.btn-primary:hover{{background:#2563eb}}
.btn-green{{background:var(--green);color:#fff}}.btn-green:hover{{background:#15803d}}
.btn-row{{display:flex;gap:8px}}
.meta-item{{font-size:13px;padding:2px 0}}
</style>
</head>
<body>
<header>
  <h1>Kensa Rule Review</h1>
  <a href="/">← Back to Coverage Report</a>
</header>
<main>
  <div class="breadcrumb"><a href="/">Coverage Report</a> / <a href="/#rules">Rules</a> / <strong>{r["id"]}</strong></div>

  <div class="rule-header">
    <h2><code>{r["id"]}</code> {flag_badge}</h2>
    <p>{r.get("title", "")}</p>
  </div>

  <div class="meta-grid">
    <div class="meta-card"><div class="label">Severity</div><div class="value"><span class="badge badge-{r.get("severity", "medium")}">{r.get("severity", "—")}</span></div></div>
    <div class="meta-card"><div class="label">Category</div><div class="value">{r.get("category", "—")}</div></div>
    <div class="meta-card"><div class="label">Tags</div><div class="value">{tags_html or "—"}</div></div>
  </div>

  {"" if not r.get("description") else f'<div class="detail-section"><h3>Description</h3><p>{_esc(r["description"])}</p></div>'}
  {"" if not r.get("rationale") else f'<div class="detail-section"><h3>Rationale</h3><p>{_esc(r["rationale"])}</p></div>'}
  {refs_html}
  {plats_html}
  {impls_html}

  {reviews_html}

  <div class="review-form">
    <h3>Add Review</h3>
    <form method="POST" action="/rule/{r["id"]}/review">
      <div class="form-row">
        <label>Flag Type</label>
        <select name="flag">{flag_options}</select>
      </div>
      <div class="form-row">
        <label>Reviewer</label>
        <input type="text" name="reviewer" value="human" required>
      </div>
      <div class="form-row">
        <label>Note</label>
        <textarea name="note" placeholder="Describe the issue or finding..."></textarea>
      </div>
      <div class="btn-row">
        <button type="submit" class="btn btn-primary">Submit Review</button>
        {"" if not flag_status else '<button type="submit" class="btn btn-green" onclick="this.form.querySelector(&#39;select[name=flag]&#39;).value=&#39;cleared&#39;">Clear Flag</button>'}
      </div>
    </form>
  </div>

</main>
</body>
</html>"""


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def create_app(
    rules: dict[str, dict],
    mappings: dict[str, dict],
    control_titles: dict[str, str],
    history: list[dict],
    db_path: Path | None = None,
) -> Flask:
    """Create the Flask app with pre-loaded data."""
    app = Flask(__name__)

    # Open/create review DB
    _db_path = db_path or REVIEW_DB
    conn = open_review_db(_db_path)
    app.config["REVIEW_DB_PATH"] = str(_db_path)

    def get_db() -> sqlite3.Connection:
        """Get a DB connection (reuse or reopen)."""
        return open_review_db(Path(app.config["REVIEW_DB_PATH"]))

    # Store static data for re-rendering
    app.config["RULES"] = rules
    app.config["MAPPINGS"] = mappings
    app.config["CONTROL_TITLES"] = control_titles
    app.config["HISTORY"] = history

    conn.close()

    @app.route("/")
    def index():
        db = get_db()
        live_reviews = get_all_reviews(db)
        db.close()
        data = compute_data(mappings, rules, control_titles, live_reviews)
        base_html = render_html(data, history)
        return _rewrite_rule_links(base_html)

    @app.route("/rule/<rule_id>")
    def rule_detail(rule_id):
        rule = rules.get(rule_id)
        if not rule:
            abort(404)
        db = get_db()
        entries = get_rule_reviews(db, rule_id)
        flag = compute_flag_status(db, rule_id)
        db.close()
        return _render_rule_page(rule, entries, flag)

    @app.route("/rule/<rule_id>/review", methods=["POST"])
    def rule_review_form(rule_id):
        """Handle form POST from rule detail page."""
        if rule_id not in rules:
            abort(404)
        flag = request.form.get("flag", "")
        reviewer = request.form.get("reviewer", "human")
        note = request.form.get("note", "")
        if flag not in VALID_FLAGS:
            abort(400)
        db = get_db()
        add_review(db, rule_id, reviewer, flag, note)
        db.close()
        return redirect(url_for("rule_detail", rule_id=rule_id))

    @app.route("/api/reviews", methods=["GET"])
    def api_list_reviews():
        rule_id = request.args.get("rule_id")
        db = get_db()
        if rule_id:
            entries = get_rule_reviews(db, rule_id)
            flag = compute_flag_status(db, rule_id)
            db.close()
            return jsonify(
                {"rule_id": rule_id, "entries": entries, "flag_status": flag}
            )
        reviews = get_all_reviews(db)
        db.close()
        return jsonify(reviews)

    @app.route("/api/reviews/<rule_id>", methods=["GET"])
    def api_rule_reviews(rule_id):
        db = get_db()
        entries = get_rule_reviews(db, rule_id)
        flag = compute_flag_status(db, rule_id)
        db.close()
        return jsonify({"rule_id": rule_id, "entries": entries, "flag_status": flag})

    @app.route("/api/reviews", methods=["POST"])
    def api_add_review():
        body = request.get_json(silent=True) or {}
        rule_id = body.get("rule_id")
        flag = body.get("flag")
        if not rule_id:
            return jsonify({"error": "rule_id is required"}), 400
        if not flag:
            return jsonify({"error": "flag is required"}), 400
        if flag not in VALID_FLAGS:
            return jsonify(
                {"error": f"Invalid flag. Must be one of: {VALID_FLAGS}"}
            ), 400
        reviewer = body.get("reviewer", "unknown")
        note = body.get("note", "")
        db = get_db()
        row = add_review(db, rule_id, reviewer, flag, note, date_str=body.get("date"))
        row["flag_status"] = compute_flag_status(db, rule_id)
        db.close()
        return jsonify(row), 201

    @app.route("/api/reviews/<int:review_id>", methods=["DELETE"])
    def api_delete_review(review_id):
        db = get_db()
        deleted = delete_review(db, review_id)
        db.close()
        if deleted:
            return "", 204
        return jsonify({"error": "Not found"}), 404

    @app.route("/api/summary")
    def api_summary():
        db = get_db()
        summary = get_review_summary(db)
        db.close()
        return jsonify(summary)

    return app


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    """Start the review server."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5050, help="Port (default: 5050)")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    args = parser.parse_args()

    print("Loading rules...", file=sys.stderr)
    rules = load_rules()
    print(f"  {len(rules)} rules loaded", file=sys.stderr)

    print("Loading mappings...", file=sys.stderr)
    mappings = load_mappings()
    print(f"  {len(mappings)} mappings loaded", file=sys.stderr)

    print("Loading context baselines...", file=sys.stderr)
    control_titles = load_control_titles()
    print(f"  {len(control_titles)} control titles loaded", file=sys.stderr)

    print("Opening review database...", file=sys.stderr)
    conn = open_review_db()
    imported = import_from_yaml(conn)
    if imported:
        print(f"  Imported {imported} entries from review.yaml", file=sys.stderr)
    review_count = conn.execute("SELECT COUNT(*) as c FROM reviews").fetchone()["c"]
    print(f"  {review_count} review entries in DB", file=sys.stderr)
    conn.close()

    print("Loading history...", file=sys.stderr)
    try:
        hist_conn = open_db()
        history = load_history(hist_conn)
        hist_conn.close()
    except Exception:
        history = []

    app = create_app(rules, mappings, control_titles, history)

    print(
        f"\n  Review server running at http://{args.host}:{args.port}\n",
        file=sys.stderr,
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
