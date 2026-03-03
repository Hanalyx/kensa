#!/usr/bin/env python3
"""Generate a self-contained HTML coverage report for Kensa rules and frameworks.

Usage:
    python3 scripts/coverage_report.py                  # generate + save snapshot
    python3 scripts/coverage_report.py --no-history     # generate without saving
    python3 scripts/coverage_report.py --output /tmp/kensa.html

History is persisted to reports/history.db (SQLite, gitignored).
Each run appends a snapshot only when coverage numbers have changed.
The report embeds all history for trend sparklines and delta comparisons.

Output: reports/coverage.html (gitignored — local visibility only)
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
MAPPINGS_DIR = ROOT / "mappings"
RULES_DIR = ROOT / "rules"
CONTEXT_DIR = ROOT / "context"
OUTPUT_DIR = ROOT / "reports"
HISTORY_DB = OUTPUT_DIR / "history.db"

CATEGORIES = [
    "access-control",
    "audit",
    "filesystem",
    "kernel",
    "logging",
    "network",
    "services",
    "system",
]

FRAMEWORK_ORDER = [
    "cis-rhel9-v2.0.0",
    "cis-rhel8-v4.0.0",
    "stig-rhel9-v2r7",
    "stig-rhel8-v2r6",
    "nist-800-53-r5",
    "fedramp-moderate",
    "pci-dss-v4.0",
]

FRAMEWORK_SHORT = {
    "cis-rhel9-v2.0.0": "CIS9",
    "cis-rhel8-v4.0.0": "CIS8",
    "stig-rhel9-v2r7": "STIG9",
    "stig-rhel8-v2r6": "STIG8",
    "nist-800-53-r5": "NIST",
    "fedramp-moderate": "FedRAMP",
    "pci-dss-v4.0": "PCI-DSS",
}

# ── SQLite history ─────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_at TEXT    NOT NULL,
    total_rules  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fw_snapshots (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
    fw_id        TEXT    NOT NULL,
    implemented  INTEGER NOT NULL,
    unimplemented INTEGER NOT NULL,
    total        INTEGER NOT NULL,
    pct          REAL    NOT NULL,
    PRIMARY KEY (snapshot_id, fw_id)
);
CREATE TABLE IF NOT EXISTS matrix_snapshots (
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
    category     TEXT    NOT NULL,
    fw_id        TEXT    NOT NULL,
    count        INTEGER NOT NULL,
    total        INTEGER NOT NULL,
    pct          REAL    NOT NULL,
    PRIMARY KEY (snapshot_id, category, fw_id)
);
"""


def open_db() -> sqlite3.Connection:
    """Open (or create) the history database."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(HISTORY_DB)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def build_snapshot(data: dict) -> dict:
    """Extract lightweight snapshot dict from computed report data."""
    return {
        "generated_at": data["generated_at"],
        "total_rules": data["total_rules"],
        "frameworks": {
            f["id"]: {
                "implemented": f["implemented"],
                "unimplemented": f["unimplemented"],
                "total": f["total"],
                "pct": f["coverage_pct"],
            }
            for f in data["frameworks"]
        },
        "matrix": {
            cat: {
                fw_id: {"count": cell["count"], "pct": cell["pct"]}
                for fw_id, cell in fw_data.items()
            }
            for cat, fw_data in data["matrix"].items()
        },
    }


def _fw_data_changed(conn: sqlite3.Connection, snapshot: dict) -> bool:
    """Return True if framework coverage differs from the most recent snapshot."""
    row = conn.execute(
        "SELECT id FROM snapshots ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return True
    last_id = row["id"]
    for fw_id, fw in snapshot["frameworks"].items():
        prev = conn.execute(
            "SELECT pct, implemented FROM fw_snapshots WHERE snapshot_id=? AND fw_id=?",
            (last_id, fw_id),
        ).fetchone()
        if prev is None or prev["pct"] != fw["pct"] or prev["implemented"] != fw["implemented"]:
            return True
    prev_rules = conn.execute(
        "SELECT total_rules FROM snapshots WHERE id=?", (last_id,)
    ).fetchone()
    if prev_rules and prev_rules["total_rules"] != snapshot["total_rules"]:
        return True
    return False


def save_snapshot(conn: sqlite3.Connection, snapshot: dict) -> bool:
    """Persist snapshot to DB if data changed. Returns True if saved."""
    if not _fw_data_changed(conn, snapshot):
        return False
    cur = conn.execute(
        "INSERT INTO snapshots (generated_at, total_rules) VALUES (?, ?)",
        (snapshot["generated_at"], snapshot["total_rules"]),
    )
    snap_id = cur.lastrowid
    for fw_id, fw in snapshot["frameworks"].items():
        conn.execute(
            "INSERT INTO fw_snapshots VALUES (?,?,?,?,?,?)",
            (snap_id, fw_id, fw["implemented"], fw["unimplemented"], fw["total"], fw["pct"]),
        )
    for cat, fw_data in snapshot["matrix"].items():
        for fw_id, cell in fw_data.items():
            conn.execute(
                "INSERT INTO matrix_snapshots VALUES (?,?,?,?,?,?)",
                (snap_id, cat, fw_id, cell["count"],
                 snapshot["frameworks"].get(fw_id, {}).get("total", 0), cell["pct"]),
            )
    conn.commit()
    return True


def load_history(conn: sqlite3.Connection) -> list[dict]:
    """Load all snapshots from DB as a list (oldest first) for embedding in HTML."""
    snapshots = []
    for snap in conn.execute("SELECT * FROM snapshots ORDER BY id ASC").fetchall():
        fw_rows = conn.execute(
            "SELECT * FROM fw_snapshots WHERE snapshot_id=?", (snap["id"],)
        ).fetchall()
        frameworks = {
            r["fw_id"]: {
                "implemented": r["implemented"],
                "unimplemented": r["unimplemented"],
                "total": r["total"],
                "pct": r["pct"],
            }
            for r in fw_rows
        }
        snapshots.append(
            {
                "id": snap["id"],
                "generated_at": snap["generated_at"],
                "total_rules": snap["total_rules"],
                "frameworks": frameworks,
            }
        )
    return snapshots


# ── Data loading ───────────────────────────────────────────────────────────────

def load_rules() -> dict[str, dict]:
    """Load all rule YAMLs keyed by rule ID."""
    rules = {}
    for f in RULES_DIR.rglob("*.yml"):
        try:
            data = yaml.safe_load(f.read_text())
            if data and "id" in data:
                rules[data["id"]] = data
        except Exception as e:
            print(f"Warning: could not load rule {f}: {e}", file=sys.stderr)
    return rules


def load_mappings() -> dict[str, dict]:
    """Load all framework mapping YAMLs keyed by framework ID."""
    mappings = {}
    for f in MAPPINGS_DIR.rglob("*.yaml"):
        try:
            data = yaml.safe_load(f.read_text())
            if data and "id" in data:
                mappings[data["id"]] = data
        except Exception as e:
            print(f"Warning: could not load mapping {f}: {e}", file=sys.stderr)
    return mappings


def load_control_titles() -> dict[str, str]:
    """Build flat control_id -> title lookup from all context baselines."""
    titles: dict[str, str] = {}
    cis_dir = CONTEXT_DIR / "cis"
    if cis_dir.exists():
        for f in cis_dir.glob("*.yaml"):
            try:
                d = yaml.safe_load(f.read_text())
                for ch in (d.get("chapters") or {}).values():
                    for ctrl in ch.get("controls", []):
                        if ctrl.get("id"):
                            titles[ctrl["id"]] = ctrl.get("title", "")
            except Exception:
                pass
    fedramp_f = CONTEXT_DIR / "fedramp" / "moderate-rev5-baseline.yaml"
    if fedramp_f.exists():
        try:
            d = yaml.safe_load(fedramp_f.read_text())
            for fam in d.get("families", {}).values():
                for ctrl in fam.get("controls", []):
                    if ctrl.get("id"):
                        titles[ctrl["id"]] = ctrl.get("title", "")
        except Exception:
            pass
    return titles


def compute_data(
    mappings: dict[str, dict],
    rules: dict[str, dict],
    control_titles: dict[str, str],
) -> dict:
    """Build the full data structure for the HTML report."""
    rule_to_frameworks: dict[str, list[str]] = {}
    frameworks_data = []

    for fw_id in FRAMEWORK_ORDER:
        m = mappings.get(fw_id)
        if not m:
            continue
        controls = m.get("controls", {})
        unimplemented = m.get("unimplemented", {})

        impl_controls = []
        for ctrl_id, ctrl_data in controls.items():
            rule_ids = ctrl_data.get("rules", [])
            title = ctrl_data.get("title") or control_titles.get(ctrl_id, "")
            impl_controls.append(
                {
                    "id": ctrl_id,
                    "title": title,
                    "rules": rule_ids,
                    "level": ctrl_data.get("level", ""),
                    "severity": ctrl_data.get("severity", ""),
                }
            )
            for rule_id in rule_ids:
                rule_to_frameworks.setdefault(rule_id, [])
                if fw_id not in rule_to_frameworks[rule_id]:
                    rule_to_frameworks[rule_id].append(fw_id)

        unimp_controls = []
        for ctrl_id, ctrl_data in unimplemented.items():
            title = ctrl_data.get("title") or control_titles.get(ctrl_id, "")
            unimp_controls.append(
                {
                    "id": ctrl_id,
                    "title": title,
                    "reason": ctrl_data.get("reason", ""),
                    "type": ctrl_data.get("type", ""),
                }
            )

        total = len(impl_controls) + len(unimp_controls)
        coverage_pct = round(len(impl_controls) / total * 100, 1) if total else 0.0

        platform = m.get("platform", {})
        platform_str = ""
        if platform:
            family = platform.get("family", "")
            mn = platform.get("min_version", "")
            mx = platform.get("max_version", "")
            if family:
                platform_str = f"{family} {mn}–{mx}" if mn else family

        frameworks_data.append(
            {
                "id": fw_id,
                "short": FRAMEWORK_SHORT.get(fw_id, fw_id),
                "title": m.get("title", fw_id),
                "framework_type": m.get("framework", ""),
                "platform": platform_str,
                "total": total,
                "implemented": len(impl_controls),
                "unimplemented": len(unimp_controls),
                "coverage_pct": coverage_pct,
                "impl_controls": sorted(impl_controls, key=lambda x: x["id"]),
                "unimp_controls": sorted(unimp_controls, key=lambda x: x["id"]),
            }
        )

    rules_data = [
        {
            "id": rule_id,
            "title": rule.get("title", ""),
            "category": rule.get("category", ""),
            "severity": rule.get("severity", ""),
            "frameworks": rule_to_frameworks.get(rule_id, []),
        }
        for rule_id, rule in sorted(rules.items())
    ]

    matrix: dict[str, dict[str, dict]] = {}
    for cat in CATEGORIES:
        matrix[cat] = {}
        total_in_cat = sum(1 for r in rules.values() if r.get("category") == cat)
        for fw_id in FRAMEWORK_ORDER:
            m = mappings.get(fw_id)
            if not m:
                matrix[cat][fw_id] = {"count": 0, "total": total_in_cat, "pct": 0}
                continue
            all_fw_rules: set[str] = set()
            for ctrl_data in m.get("controls", {}).values():
                all_fw_rules.update(ctrl_data.get("rules", []))
            count = sum(
                1 for rid in all_fw_rules if rules.get(rid, {}).get("category") == cat
            )
            matrix[cat][fw_id] = {
                "count": count,
                "total": total_in_cat,
                "pct": round(count / total_in_cat * 100, 1) if total_in_cat else 0,
            }

    # Framework-completeness matrix (View B):
    # cell(cat, fw) = "of fw's total controls, how many are covered by category-cat rules?"
    # Columns sum to the framework's overall coverage %.
    matrix_b: dict[str, dict[str, dict]] = {}
    fw_totals = {f["id"]: f["total"] for f in frameworks_data}
    for cat in CATEGORIES:
        matrix_b[cat] = {}
        for fw_id in FRAMEWORK_ORDER:
            m = mappings.get(fw_id)
            fw_total = fw_totals.get(fw_id, 0)
            if not m or not fw_total:
                matrix_b[cat][fw_id] = {"count": 0, "total": fw_total, "pct": 0}
                continue
            count = sum(
                1
                for ctrl_data in m.get("controls", {}).values()
                if any(
                    rules.get(rid, {}).get("category") == cat
                    for rid in ctrl_data.get("rules", [])
                )
            )
            matrix_b[cat][fw_id] = {
                "count": count,
                "total": fw_total,
                "pct": round(count / fw_total * 100, 1) if fw_total else 0,
            }

    category_stats = [
        {
            "name": cat,
            "rule_count": sum(1 for r in rules.values() if r.get("category") == cat),
        }
        for cat in CATEGORIES
    ]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_rules": len(rules),
        "total_frameworks": len(frameworks_data),
        "frameworks": frameworks_data,
        "rules": rules_data,
        "matrix": matrix,
        "matrix_b": matrix_b,
        "categories": category_stats,
        "framework_order": FRAMEWORK_ORDER,
        "framework_short": FRAMEWORK_SHORT,
    }


# ── HTML renderer ──────────────────────────────────────────────────────────────

def render_html(data: dict, history: list[dict]) -> str:
    """Render the full self-contained HTML report."""
    data_json = json.dumps(data, separators=(",", ":"))
    history_json = json.dumps(history, separators=(",", ":"))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kensa Coverage Report</title>
<style>
:root {{
  --bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;
  --accent:#3b82f6;--green:#16a34a;--lime:#65a30d;--yellow:#ca8a04;
  --orange:#ea580c;--red:#dc2626;--gray:#94a3b8;
  --green-bg:#dcfce7;--lime-bg:#ecfccb;--yellow-bg:#fef9c3;
  --orange-bg:#ffedd5;--red-bg:#fee2e2;--gray-bg:#f1f5f9;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px}}
header{{background:#1e293b;color:#fff;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}}
header h1{{font-size:18px;font-weight:600}}
header .meta{{font-size:12px;color:#94a3b8}}
nav{{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex}}
nav button{{background:none;border:none;padding:12px 16px;cursor:pointer;font-size:13px;color:var(--muted);border-bottom:2px solid transparent;transition:all .15s}}
nav button:hover{{color:var(--text)}}
nav button.active{{color:var(--accent);border-bottom-color:var(--accent);font-weight:500}}
main{{padding:24px;max-width:1400px;margin:0 auto}}
section{{display:none}}
section.active{{display:block}}
h2{{font-size:16px;font-weight:600;margin-bottom:16px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.stat{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}}
.stat .val{{font-size:28px;font-weight:700;color:var(--accent)}}
.stat .lbl{{font-size:12px;color:var(--muted);margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:8px 12px;background:#f1f5f9;border-bottom:2px solid var(--border);font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}}
td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#f8fafc}}
.badge{{display:inline-block;padding:2px 7px;border-radius:9999px;font-size:11px;font-weight:500}}
.badge-critical{{background:#fee2e2;color:#dc2626}}
.badge-high{{background:#ffedd5;color:#ea580c}}
.badge-medium{{background:#fef9c3;color:#ca8a04}}
.badge-low{{background:#dcfce7;color:#16a34a}}
.badge-info{{background:#eff6ff;color:#3b82f6}}
.pct-bar{{display:flex;align-items:center;gap:8px}}
.bar-wrap{{flex:1;background:#e2e8f0;border-radius:4px;height:8px;min-width:60px}}
.bar-fill{{height:8px;border-radius:4px}}
.pct-num{{font-weight:600;min-width:42px;text-align:right;font-size:13px}}
.tag{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;background:#eff6ff;color:#3b82f6;margin:1px}}
input[type=search]{{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:6px;font-size:13px;outline:none;margin-bottom:0}}
input[type=search]:focus{{border-color:var(--accent);box-shadow:0 0 0 2px #bfdbfe}}
select{{padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;outline:none;background:#fff}}
.heatmap-wrap{{overflow-x:auto}}
.heatmap{{border-collapse:collapse}}
.heatmap th{{padding:8px 12px;font-size:12px}}
.heatmap td{{padding:0;border:1px solid var(--border)}}
.hm-cell{{padding:8px 10px;text-align:center;min-width:82px}}
.hm-cell .pct{{font-size:14px;font-weight:700}}
.hm-cell .cnt{{font-size:11px;color:var(--muted);margin-top:2px}}
.hm-row-label{{font-weight:500;padding:8px 12px;white-space:nowrap;background:#f8fafc}}
.c-green{{background:var(--green-bg);color:var(--green)}}
.c-lime{{background:var(--lime-bg);color:var(--lime)}}
.c-yellow{{background:var(--yellow-bg);color:var(--yellow)}}
.c-orange{{background:var(--orange-bg);color:var(--orange)}}
.c-red{{background:var(--red-bg);color:var(--red)}}
.c-zero{{background:var(--gray-bg);color:var(--gray)}}
.accordion{{border:1px solid var(--border);border-radius:8px;margin-bottom:12px;overflow:hidden}}
.acc-hdr{{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:#f8fafc;cursor:pointer;user-select:none}}
.acc-hdr:hover{{background:#f1f5f9}}
.acc-hdr .fw-title{{font-weight:600;font-size:14px}}
.acc-hdr .fw-meta{{font-size:12px;color:var(--muted);margin-top:2px}}
.acc-hdr .chevron{{transition:transform .2s;font-size:12px;color:var(--muted)}}
.acc-hdr.open .chevron{{transform:rotate(90deg)}}
.acc-body{{display:none;padding:16px;border-top:1px solid var(--border)}}
.acc-body.open{{display:block}}
.tabs-inner{{display:flex;border-bottom:1px solid var(--border);margin-bottom:12px}}
.tab-btn{{background:none;border:none;padding:8px 14px;cursor:pointer;font-size:13px;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px}}
.tab-btn.active{{color:var(--accent);border-bottom-color:var(--accent);font-weight:500}}
.tab-pane{{display:none}}
.tab-pane.active{{display:block}}
.legend{{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;margin-top:12px}}
.legend-item{{display:flex;align-items:center;gap:5px}}
.legend-dot{{width:12px;height:12px;border-radius:2px}}
.fw-check{{color:var(--green);font-weight:700}}
.fw-dash{{color:#e2e8f0}}
.empty{{color:var(--muted);font-style:italic;padding:12px 0;text-align:center}}
.delta-up{{color:var(--green);font-size:12px;font-weight:600}}
.delta-dn{{color:var(--red);font-size:12px;font-weight:600}}
.delta-eq{{color:var(--gray);font-size:12px}}
.sparkline-cell{{min-width:110px}}
.hist-table td{{vertical-align:middle}}
</style>
</head>
<body>
<header>
  <h1>Kensa Coverage Report</h1>
  <div class="meta" id="meta-bar">Loading...</div>
</header>
<nav>
  <button class="active" onclick="showTab('summary')">Summary</button>
  <button onclick="showTab('heatmap')">Heatmap</button>
  <button onclick="showTab('frameworks')">Frameworks</button>
  <button onclick="showTab('rules')">Rules</button>
  <button onclick="showTab('history')">History</button>
</nav>
<main>
  <section id="tab-summary" class="active"></section>
  <section id="tab-heatmap"></section>
  <section id="tab-frameworks"></section>
  <section id="tab-rules"></section>
  <section id="tab-history"></section>
</main>
<script>
const DATA = {data_json};
const HISTORY = {history_json};

// ── Helpers ──────────────────────────────────────────────────────────────────
function pctColor(p) {{
  if(p>=80) return 'var(--green)'; if(p>=60) return 'var(--lime)';
  if(p>=40) return 'var(--yellow)'; if(p>=20) return 'var(--orange)';
  if(p>0)   return 'var(--red)';   return 'var(--gray)';
}}
function pctClass(p) {{
  if(p>=80) return 'c-green'; if(p>=60) return 'c-lime';
  if(p>=40) return 'c-yellow'; if(p>=20) return 'c-orange';
  if(p>0)   return 'c-red';   return 'c-zero';
}}
function pctBar(p) {{
  const col=pctColor(p);
  return `<div class="pct-bar"><div class="bar-wrap"><div class="bar-fill" style="width:${{p}}%;background:${{col}}"></div></div><span class="pct-num" style="color:${{col}}">${{p}}%</span></div>`;
}}
function severityBadge(s) {{
  const m={{critical:'badge-critical',high:'badge-high',medium:'badge-medium',low:'badge-low'}};
  const c=m[s?.toLowerCase()]||'badge-info';
  return s?`<span class="badge ${{c}}">${{s}}</span>`:'';
}}
function delta(curr, prev) {{
  if(prev===undefined||prev===null) return '<span class="delta-eq">—</span>';
  const d=+(curr-prev).toFixed(1);
  if(Math.abs(d)<0.05) return '<span class="delta-eq">→</span>';
  return d>0
    ? `<span class="delta-up">▲ +${{d}}%</span>`
    : `<span class="delta-dn">▼ ${{d}}%</span>`;
}}
function sparkline(values, w=110, h=28) {{
  if(!values||values.length<2) return '<span style="color:var(--muted);font-size:11px">no data</span>';
  const mn=Math.min(...values), mx=Math.max(...values), rng=mx-mn||1;
  const pts=values.map((v,i)=>{{
    const x=(i/(values.length-1))*w;
    const y=h-2-((v-mn)/rng)*(h-4);
    return `${{x.toFixed(1)}},${{y.toFixed(1)}}`;
  }}).join(' ');
  const last=values[values.length-1], first=values[0];
  const col=last>=first?'var(--green)':'var(--red)';
  const ex=(values.length-1)/(values.length-1)*w;
  const ey=h-2-((last-mn)/rng)*(h-4);
  return `<svg width="${{w}}" height="${{h}}" style="display:block;vertical-align:middle">
    <polyline points="${{pts}}" fill="none" stroke="${{col}}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="${{ex.toFixed(1)}}" cy="${{ey.toFixed(1)}}" r="2.5" fill="${{col}}"/>
  </svg>`;
}}
function showTab(name) {{
  const names=['summary','heatmap','frameworks','rules','history'];
  document.querySelectorAll('nav button').forEach((b,i)=>b.classList.toggle('active',names[i]===name));
  document.querySelectorAll('main section').forEach(s=>s.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
}}

// ── Summary ──────────────────────────────────────────────────────────────────
function renderSummary() {{
  const d=DATA;
  const prev=HISTORY.length>=2?HISTORY[HISTORY.length-2]:null;
  document.getElementById('meta-bar').textContent=
    `${{d.total_rules}} rules · ${{d.total_frameworks}} frameworks · Generated ${{d.generated_at}} · ${{HISTORY.length}} snapshot${{HISTORY.length!==1?'s':''}} stored`;

  const rows=d.frameworks.map(f=>{{
    const prevPct=prev?.frameworks?.[f.id]?.pct;
    return `<tr>
      <td><strong>${{f.id}}</strong><br><span style="color:var(--muted);font-size:12px">${{f.title}}</span></td>
      <td>${{f.platform||'—'}}</td>
      <td style="text-align:center">${{f.total}}</td>
      <td style="text-align:center;color:var(--green)">${{f.implemented}}</td>
      <td style="text-align:center;color:var(--red)">${{f.unimplemented}}</td>
      <td style="min-width:160px">${{pctBar(f.coverage_pct)}}</td>
      <td style="text-align:center">${{delta(f.coverage_pct,prevPct)}}</td>
    </tr>`;
  }}).join('');

  const deltaNote=prev
    ? `<p style="color:var(--muted);font-size:12px;margin-bottom:16px">Δ column compares to previous snapshot: <strong>${{prev.generated_at}}</strong></p>`
    : `<p style="color:var(--muted);font-size:12px;margin-bottom:16px">No previous snapshot — run again after making changes to see deltas.</p>`;

  document.getElementById('tab-summary').innerHTML=`
    <h2>Coverage Summary</h2>
    <div class="stats-grid">
      <div class="stat"><div class="val">${{d.total_rules}}</div><div class="lbl">Total Rules</div></div>
      <div class="stat"><div class="val">${{d.total_frameworks}}</div><div class="lbl">Frameworks</div></div>
      <div class="stat"><div class="val">${{d.categories.length}}</div><div class="lbl">Categories</div></div>
      <div class="stat"><div class="val">${{HISTORY.length}}</div><div class="lbl">History Snapshots</div></div>
    </div>
    ${{deltaNote}}
    <div class="card">
      <table>
        <thead><tr>
          <th>Framework</th><th>Platform</th>
          <th style="text-align:center">Total</th>
          <th style="text-align:center">Implemented</th>
          <th style="text-align:center">Unimplemented</th>
          <th>Coverage</th>
          <th style="text-align:center">Δ vs Prev</th>
        </tr></thead>
        <tbody>${{rows}}</tbody>
      </table>
    </div>
    <div class="legend">
      <strong>Scale:</strong>
      <span class="legend-item"><span class="legend-dot" style="background:var(--green-bg);border:1px solid var(--green)"></span>≥80%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--lime-bg);border:1px solid var(--lime)"></span>60–79%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--yellow-bg);border:1px solid var(--yellow)"></span>40–59%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--orange-bg);border:1px solid var(--orange)"></span>20–39%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--red-bg);border:1px solid var(--red)"></span>&lt;20%</span>
    </div>`;
}}

// ── Heatmap ───────────────────────────────────────────────────────────────────
let _hmView = 'a';

function renderHeatmap() {{
  const d=DATA;
  const fws=d.framework_order.filter(id=>d.frameworks.find(f=>f.id===id));
  const hdrs=fws.map(id=>`<th style="text-align:center">${{d.framework_short[id]||id}}</th>`).join('');

  const descA=`<strong>View A — Rule utilisation:</strong> of all Kensa rules in this category, how many are referenced by the framework?`;
  const descB=`<strong>View B — Framework completeness:</strong> of all the framework's total controls, how many are covered by rules in this category? <em>Each column sums to the framework's overall coverage %.</em>`;

  function buildRows(view) {{
    const mx = view==='a' ? d.matrix : d.matrix_b;
    const catRows = d.categories.map(cat=>{{
      const cells=fws.map(fw=>{{
        const c=mx[cat.name]?.[fw];
        if(!c||c.total===0) return `<td><div class="hm-cell c-zero"><div class="pct">—</div></div></td>`;
        return `<td><div class="hm-cell ${{pctClass(c.pct)}}"><div class="pct">${{c.pct}}%</div><div class="cnt">${{c.count}}/${{c.total}}</div></div></td>`;
      }}).join('');
      const label = view==='a'
        ? `${{cat.name}}<br><span style="font-size:11px;color:var(--muted)">${{cat.rule_count}} rules</span>`
        : `${{cat.name}}`;
      return `<tr><td class="hm-row-label">${{label}}</td>${{cells}}</tr>`;
    }});

    if(view==='b') {{
      // Footer row: overall coverage per framework (= sum of matrix_b column)
      const totalCells=fws.map(fw=>{{
        const fw_info=d.frameworks.find(f=>f.id===fw);
        if(!fw_info) return `<td></td>`;
        const pct=fw_info.coverage_pct;
        return `<td><div class="hm-cell ${{pctClass(pct)}}" style="font-weight:700"><div class="pct">${{pct}}%</div><div class="cnt">total</div></div></td>`;
      }}).join('');
      catRows.push(`<tr style="border-top:2px solid var(--border)"><td class="hm-row-label" style="font-weight:700">Overall coverage</td>${{totalCells}}</tr>`);
    }}
    return catRows.join('');
  }}

  function mount() {{
    document.getElementById('hm-desc').innerHTML = _hmView==='a' ? descA : descB;
    document.getElementById('hm-body').innerHTML = buildRows(_hmView);
    document.querySelectorAll('.hm-toggle').forEach(b=>b.classList.toggle('active', b.dataset.view===_hmView));
  }}

  document.getElementById('tab-heatmap').innerHTML=`
    <h2>Category × Framework Heatmap</h2>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">
      <div style="display:flex;border:1px solid var(--border);border-radius:6px;overflow:hidden">
        <button class="hm-toggle active" data-view="a"
          onclick="_hmView='a';document.querySelectorAll('.hm-toggle').forEach(b=>b.classList.toggle('active',b.dataset.view==='a'));document.getElementById('hm-desc').innerHTML='${{descA.replace(/'/g,"\\'")}}'.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');document.getElementById('hm-body').innerHTML=buildRows('a')"
          style="padding:6px 14px;font-size:13px;border:none;cursor:pointer;background:#f1f5f9;color:var(--muted)">
          View A: Rule utilisation
        </button>
        <button class="hm-toggle" data-view="b"
          onclick="_hmView='b';document.querySelectorAll('.hm-toggle').forEach(b=>b.classList.toggle('active',b.dataset.view==='b'));document.getElementById('hm-desc').innerHTML='${{descB.replace(/'/g,"\\'")}}'.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&lt;em&gt;/g,'<em>').replace(/&lt;\\/em&gt;/g,'<\\/em>');document.getElementById('hm-body').innerHTML=buildRows('b')"
          style="padding:6px 14px;font-size:13px;border:none;cursor:pointer;background:white;color:var(--text)">
          View B: Framework completeness
        </button>
      </div>
    </div>
    <p id="hm-desc" style="color:var(--muted);font-size:13px;margin-bottom:16px">${{descA}}</p>
    <div class="card"><div class="heatmap-wrap">
      <table class="heatmap">
        <thead><tr><th>Category</th>${{hdrs}}</tr></thead>
        <tbody id="hm-body"></tbody>
      </table>
    </div></div>
    <div class="legend"><strong>Scale:</strong>
      <span class="legend-item"><span class="legend-dot" style="background:var(--green-bg);border:1px solid var(--green)"></span>≥80%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--lime-bg);border:1px solid var(--lime)"></span>60–79%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--yellow-bg);border:1px solid var(--yellow)"></span>40–59%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--orange-bg);border:1px solid var(--orange)"></span>20–39%</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--red-bg);border:1px solid var(--red)"></span>&lt;20%</span>
    </div>`;

  // Active toggle style
  document.querySelectorAll('.hm-toggle').forEach(b=>{{
    b.addEventListener('click',()=>{{
      document.querySelectorAll('.hm-toggle').forEach(x=>{{
        x.style.background=x.dataset.view===_hmView?'var(--accent)':'white';
        x.style.color=x.dataset.view===_hmView?'white':'var(--text)';
      }});
    }});
  }});

  buildRows; // expose for inline onclick
  document.getElementById('hm-body').innerHTML=buildRows('a');
  // make buildRows accessible from inline onclick
  window.buildRows=buildRows;
  // fix toggle button styles properly
  document.querySelectorAll('.hm-toggle').forEach(b=>{{
    b.style.background=b.dataset.view==='a'?'var(--accent)':'white';
    b.style.color=b.dataset.view==='a'?'white':'var(--text)';
  }});
  // rewrite onclick to use window.buildRows
  document.querySelectorAll('.hm-toggle').forEach(b=>{{
    b.onclick=()=>{{
      _hmView=b.dataset.view;
      document.querySelectorAll('.hm-toggle').forEach(x=>{{
        x.style.background=x.dataset.view===_hmView?'var(--accent)':'white';
        x.style.color=x.dataset.view===_hmView?'white':'var(--text)';
      }});
      document.getElementById('hm-desc').innerHTML=_hmView==='a'?descA:descB;
      document.getElementById('hm-body').innerHTML=window.buildRows(_hmView);
    }};
  }});
}}

// ── Frameworks ────────────────────────────────────────────────────────────────
function renderFrameworks() {{
  const accordions=DATA.frameworks.map((fw,fi)=>{{
    const implRows=fw.impl_controls.map(c=>`
      <tr>
        <td><code style="font-size:12px">${{c.id}}</code></td>
        <td>${{c.title}}</td>
        <td>${{c.level||c.severity||''}}</td>
        <td>${{c.rules.map(r=>`<span class="tag">${{r}}</span>`).join(' ')}}</td>
      </tr>`).join('');
    const unimpRows=fw.unimp_controls.map(c=>`
      <tr>
        <td><code style="font-size:12px">${{c.id}}</code></td>
        <td>${{c.title}}</td>
        <td style="color:var(--muted)">${{c.type||''}}</td>
        <td style="color:var(--muted);font-size:12px">${{c.reason}}</td>
      </tr>`).join('');
    return `<div class="accordion">
      <div class="acc-hdr" onclick="toggleAcc(this)">
        <div>
          <div class="fw-title">${{fw.id}}</div>
          <div class="fw-meta">${{fw.title}}${{fw.platform?' · '+fw.platform:''}}</div>
        </div>
        <div style="display:flex;align-items:center;gap:16px">
          ${{pctBar(fw.coverage_pct)}}
          <span style="font-size:12px;color:var(--muted)">${{fw.implemented}}/${{fw.total}}</span>
          <span class="chevron">▶</span>
        </div>
      </div>
      <div class="acc-body">
        <div class="tabs-inner">
          <button class="tab-btn active" onclick="innerTab(this,'impl-${{fi}}')">Implemented (${{fw.implemented}})</button>
          <button class="tab-btn" onclick="innerTab(this,'unimp-${{fi}}')">Unimplemented (${{fw.unimplemented}})</button>
        </div>
        <div id="impl-${{fi}}" class="tab-pane active">
          ${{fw.impl_controls.length===0?'<p class="empty">None.</p>':`<table><thead><tr><th>Control ID</th><th>Title</th><th>Level/Sev</th><th>Rules</th></tr></thead><tbody>${{implRows}}</tbody></table>`}}
        </div>
        <div id="unimp-${{fi}}" class="tab-pane">
          ${{fw.unimp_controls.length===0?'<p class="empty">None.</p>':`<table><thead><tr><th>Control ID</th><th>Title</th><th>Type</th><th>Reason</th></tr></thead><tbody>${{unimpRows}}</tbody></table>`}}
        </div>
      </div>
    </div>`;
  }}).join('');
  document.getElementById('tab-frameworks').innerHTML=`
    <h2>Per-Framework Drilldown</h2>
    <p style="color:var(--muted);font-size:13px;margin-bottom:16px">Click to expand. Implemented = controls with rules. Unimplemented = known gaps.</p>
    ${{accordions}}`;
}}
function toggleAcc(h){{h.classList.toggle('open');h.nextElementSibling.classList.toggle('open');}}
function innerTab(btn,id){{
  const b=btn.closest('.acc-body');
  b.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'));
  b.querySelectorAll('.tab-pane').forEach(x=>x.classList.remove('active'));
  btn.classList.add('active');document.getElementById(id).classList.add('active');
}}

// ── Rules ─────────────────────────────────────────────────────────────────────
function renderRules() {{
  const fws=DATA.framework_order.filter(id=>DATA.frameworks.find(f=>f.id===id));
  const hdrs=fws.map(id=>`<th style="text-align:center;font-size:11px">${{DATA.framework_short[id]||id}}</th>`).join('');
  const rows=DATA.rules.map(r=>{{
    const cols=fws.map(fw=>r.frameworks.includes(fw)
      ?`<td style="text-align:center"><span class="fw-check">✓</span></td>`
      :`<td style="text-align:center"><span class="fw-dash">·</span></td>`).join('');
    return `<tr data-cat="${{r.category}}" data-sev="${{(r.severity||'').toLowerCase()}}">
      <td><code style="font-size:12px">${{r.id}}</code></td>
      <td style="max-width:280px">${{r.title}}</td>
      <td><span class="badge badge-info">${{r.category}}</span></td>
      <td>${{severityBadge(r.severity)}}</td>
      ${{cols}}
    </tr>`;
  }}).join('');
  document.getElementById('tab-rules').innerHTML=`
    <h2>Rule Cross-Reference</h2>
    <p style="color:var(--muted);font-size:13px;margin-bottom:12px">${{DATA.total_rules}} rules · ✓ = mapped to framework</p>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
      <input type="search" id="rule-search" placeholder="Search by ID or title…" style="flex:1;min-width:200px">
      <select id="rule-cat" onchange="filterRules()">
        <option value="">All categories</option>
        ${{DATA.categories.map(c=>`<option value="${{c.name}}">${{c.name}} (${{c.rule_count}})</option>`).join('')}}
      </select>
      <select id="rule-sev" onchange="filterRules()">
        <option value="">All severities</option>
        <option value="critical">Critical</option><option value="high">High</option>
        <option value="medium">Medium</option><option value="low">Low</option>
      </select>
    </div>
    <div class="card" style="padding:0;overflow:auto">
      <table><thead><tr><th>Rule ID</th><th>Title</th><th>Category</th><th>Severity</th>${{hdrs}}</tr></thead>
      <tbody id="rules-body">${{rows}}</tbody></table>
    </div>
    <div id="rules-count" style="font-size:12px;color:var(--muted);margin-top:8px"></div>`;
  document.getElementById('rule-search').addEventListener('input',filterRules);
  filterRules();
}}
function filterRules(){{
  const q=document.getElementById('rule-search').value.toLowerCase();
  const cat=document.getElementById('rule-cat').value;
  const sev=document.getElementById('rule-sev').value;
  const rows=document.querySelectorAll('#rules-body tr');
  let v=0;
  rows.forEach(r=>{{
    const m=(!q||r.textContent.toLowerCase().includes(q))&&(!cat||r.dataset.cat===cat)&&(!sev||r.dataset.sev===sev);
    r.style.display=m?'':'none';if(m)v++;
  }});
  document.getElementById('rules-count').textContent=v===rows.length?`Showing all ${{rows.length}} rules`:`Showing ${{v}} of ${{rows.length}} rules`;
}}

// ── History ───────────────────────────────────────────────────────────────────
function renderHistory() {{
  if(HISTORY.length===0){{
    document.getElementById('tab-history').innerHTML=`
      <h2>Coverage History</h2>
      <p class="empty" style="margin-top:40px">No history snapshots yet. Run the script again after making changes.</p>`;
    return;
  }}

  const fws=DATA.framework_order.filter(id=>DATA.frameworks.find(f=>f.id===id));
  const shorts=DATA.framework_short;

  // Sparkline rows — one per framework
  const sparkRows=fws.map(fw=>{{
    const values=HISTORY.map(s=>s.frameworks[fw]?.pct??null).filter(v=>v!==null);
    const last=values[values.length-1]??0;
    const first=values[0]??0;
    const trend=values.length>=2?(last>first?'\u25b2':last===first?'\u2192':'\u25bc'):'—';
    const trendCol=last>first?'var(--green)':last<first?'var(--red)':'var(--gray)';
    return `<tr>
      <td style="font-weight:500">${{fw}}</td>
      <td style="text-align:center">${{values.length}}</td>
      <td class="sparkline-cell">${{sparkline(values)}}</td>
      <td style="text-align:center">${{values.length?values[0].toFixed(1)+'%':'—'}}</td>
      <td style="text-align:center">${{values.length?values[values.length-1].toFixed(1)+'%':'—'}}</td>
      <td style="text-align:center;color:${{trendCol}};font-weight:600">${{trend}} ${{values.length>=2?(last-first>0?'+':'')+(last-first).toFixed(1)+'%':''}}</td>
    </tr>`;
  }}).join('');

  // Full history table (newest first)
  const histHdrs=fws.map(id=>`<th style="text-align:center">${{shorts[id]||id}}</th>`).join('');
  const histRows=[...HISTORY].reverse().map((snap,ri)=>{{
    const prev=ri<HISTORY.length-1?[...HISTORY].reverse()[ri+1]:null;
    const cells=fws.map(fw=>{{
      const pct=snap.frameworks[fw]?.pct;
      const prevPct=prev?.frameworks[fw]?.pct;
      if(pct===undefined) return `<td style="text-align:center;color:var(--gray)">—</td>`;
      return `<td style="text-align:center">
        <span style="color:${{pctColor(pct)}};font-weight:600">${{pct}}%</span>
        ${{delta(pct,prevPct)}}
      </td>`;
    }}).join('');
    const isLatest=ri===0;
    return `<tr${{isLatest?' style="background:#f0f9ff"':''}}>
      <td style="white-space:nowrap;font-size:12px">${{snap.generated_at}}${{isLatest?' <span class="badge badge-info">latest</span>':''}}</td>
      <td style="text-align:center">${{snap.total_rules}}</td>
      ${{cells}}
    </tr>`;
  }}).join('');

  document.getElementById('tab-history').innerHTML=`
    <h2>Coverage History</h2>
    <p style="color:var(--muted);font-size:13px;margin-bottom:20px">
      ${{HISTORY.length}} snapshot${{HISTORY.length!==1?'s':''}} stored in <code>reports/history.db</code>.
      Snapshots are saved only when coverage numbers change.
    </p>

    <h3 style="margin-bottom:12px">Trend by Framework</h3>
    <div class="card" style="padding:0;overflow:auto;margin-bottom:24px">
      <table class="hist-table">
        <thead><tr>
          <th>Framework</th><th style="text-align:center">Snapshots</th>
          <th>Trend</th><th style="text-align:center">First</th>
          <th style="text-align:center">Latest</th><th style="text-align:center">Change</th>
        </tr></thead>
        <tbody>${{sparkRows}}</tbody>
      </table>
    </div>

    <h3 style="margin-bottom:12px">All Snapshots</h3>
    <div class="card" style="padding:0;overflow:auto">
      <table class="hist-table">
        <thead><tr>
          <th>Timestamp</th><th style="text-align:center">Rules</th>${{histHdrs}}
        </tr></thead>
        <tbody>${{histRows}}</tbody>
      </table>
    </div>`;
}}

// Init
renderSummary();
renderHeatmap();
renderFrameworks();
renderRules();
renderHistory();
</script>
</body>
</html>"""


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(OUTPUT_DIR / "coverage.html"),
        help="Output HTML path (default: reports/coverage.html)",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Skip saving a snapshot to history.db",
    )
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

    print("Computing coverage data...", file=sys.stderr)
    data = compute_data(mappings, rules, control_titles)

    # History
    history: list[dict] = []
    if not args.no_history:
        print("Updating history...", file=sys.stderr)
        conn = open_db()
        snapshot = build_snapshot(data)
        saved = save_snapshot(conn, snapshot)
        history = load_history(conn)
        conn.close()
        if saved:
            print(f"  Snapshot saved ({len(history)} total)", file=sys.stderr)
        else:
            print(f"  No changes — snapshot skipped ({len(history)} total)", file=sys.stderr)
    else:
        print("History skipped (--no-history)", file=sys.stderr)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(data, history)
    out_path.write_text(html, encoding="utf-8")

    size_kb = out_path.stat().st_size // 1024
    print(f"\nReport written to: {out_path} ({size_kb} KB)", file=sys.stderr)
    print(
        f"  {data['total_rules']} rules · {data['total_frameworks']} frameworks · {len(history)} history snapshots",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
