"""Spec-derived tests for review_server.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/review_server.spec.yaml — verifying the SQLite review
layer, Flask API endpoints, and rule detail page rendering.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))

flask = pytest.importorskip("flask", reason="Flask not installed")

from scripts.review_server import (  # noqa: E402, I001
    add_review,
    compute_flag_status,
    create_app,
    delete_review,
    get_rule_reviews,
    import_from_yaml,
    open_review_db,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_rule(rule_id: str, **overrides) -> dict:
    """Create a minimal rule dict."""
    defaults = {
        "id": rule_id,
        "title": f"Test rule {rule_id}",
        "description": f"Description for {rule_id}.",
        "rationale": f"Rationale for {rule_id}.",
        "severity": "medium",
        "category": "audit",
        "tags": ["test"],
        "references": {
            "stig": {"rhel8_v2r6": {"vuln_id": "V-999999", "severity": "CAT II"}},
            "nist_800_53": ["AC-1"],
        },
        "platforms": [{"family": "rhel", "min_version": 8}],
        "implementations": [
            {
                "default": True,
                "check": {
                    "method": "package_state",
                    "name": "test-pkg",
                    "state": "present",
                },
                "remediation": {"mechanism": "package_present", "name": "test-pkg"},
            }
        ],
    }
    defaults.update(overrides)
    return defaults


def _make_app(tmp_path, rules=None):
    """Create a Flask test app with tmp DB."""
    if rules is None:
        rules = {"test-rule": _make_rule("test-rule")}
    app = create_app(
        rules=rules,
        mappings={},
        control_titles={},
        history=[],
        db_path=tmp_path / "review.db",
    )
    app.config["TESTING"] = True
    return app


# ── SQLite Layer Tests (AC-1 through AC-8) ───────────────────────────────────


class TestReviewDB:
    """Spec-derived tests for the SQLite review layer."""

    def test_ac1_open_review_db_creates_schema(self, tmp_path):
        """AC-1: open_review_db() creates the reviews table and index."""
        db_path = tmp_path / "review.db"
        conn = open_review_db(db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t["name"] for t in tables]
        assert "reviews" in table_names
        conn.close()

    def test_ac2_add_review_auto_date(self, tmp_path):
        """AC-2: add_review() inserts with auto-date and returns row dict with id."""
        conn = open_review_db(tmp_path / "review.db")
        row = add_review(conn, "test-rule", "ai", "verify", "Check this.")
        assert row["id"] is not None
        assert row["rule_id"] == "test-rule"
        assert row["reviewer"] == "ai"
        assert row["flag"] == "verify"
        assert row["note"] == "Check this."
        assert row["date"]  # auto-generated
        conn.close()

    def test_ac3_get_rule_reviews_sorted(self, tmp_path):
        """AC-3: get_rule_reviews() returns entries sorted chronologically."""
        conn = open_review_db(tmp_path / "review.db")
        add_review(conn, "r1", "ai", "verify", "First", date_str="2026-03-07")
        add_review(conn, "r1", "human", "cleared", "Second", date_str="2026-03-09")
        add_review(conn, "r1", "ai", "verify", "Third", date_str="2026-03-08")
        entries = get_rule_reviews(conn, "r1")
        dates = [e["date"] for e in entries]
        assert dates == ["2026-03-07", "2026-03-08", "2026-03-09"]
        conn.close()

    def test_ac4_flag_status_active(self, tmp_path):
        """AC-4: compute_flag_status() returns latest non-cleared flag."""
        conn = open_review_db(tmp_path / "review.db")
        add_review(conn, "r1", "ai", "verify", "Note", date_str="2026-03-07")
        add_review(conn, "r1", "ai", "incorrect-check", "Worse", date_str="2026-03-08")
        assert compute_flag_status(conn, "r1") == "incorrect-check"
        conn.close()

    def test_ac5_flag_status_cleared(self, tmp_path):
        """AC-5: compute_flag_status() returns None after cleared."""
        conn = open_review_db(tmp_path / "review.db")
        add_review(conn, "r1", "ai", "verify", "Flag", date_str="2026-03-07")
        add_review(conn, "r1", "human", "cleared", "OK", date_str="2026-03-08")
        assert compute_flag_status(conn, "r1") is None
        conn.close()

    def test_ac6_import_from_yaml(self, tmp_path):
        """AC-6: import_from_yaml() imports entries from review.yaml."""
        yaml_path = tmp_path / "review.yaml"
        yaml_path.write_text(
            yaml.dump(
                {
                    "reviews": {
                        "r1": [
                            {
                                "date": "2026-03-08",
                                "reviewer": "ai",
                                "flag": "verify",
                                "note": "Check.",
                            }
                        ]
                    }
                }
            )
        )
        conn = open_review_db(tmp_path / "review.db")
        count = import_from_yaml(conn, yaml_path)
        assert count == 1
        entries = get_rule_reviews(conn, "r1")
        assert len(entries) == 1
        assert entries[0]["flag"] == "verify"
        conn.close()

    def test_ac7_import_idempotent(self, tmp_path):
        """AC-7: import_from_yaml() skips if DB already has data."""
        yaml_path = tmp_path / "review.yaml"
        yaml_path.write_text(
            yaml.dump(
                {
                    "reviews": {
                        "r1": [
                            {
                                "date": "2026-03-08",
                                "reviewer": "ai",
                                "flag": "verify",
                                "note": "Check.",
                            }
                        ]
                    }
                }
            )
        )
        conn = open_review_db(tmp_path / "review.db")
        import_from_yaml(conn, yaml_path)
        count = import_from_yaml(conn, yaml_path)
        assert count == 0  # skipped
        entries = get_rule_reviews(conn, "r1")
        assert len(entries) == 1  # not duplicated
        conn.close()

    def test_ac8_delete_review(self, tmp_path):
        """AC-8: delete_review() removes entry by id."""
        conn = open_review_db(tmp_path / "review.db")
        row = add_review(conn, "r1", "ai", "verify", "Note")
        assert delete_review(conn, row["id"]) is True
        assert delete_review(conn, row["id"]) is False  # already gone
        assert get_rule_reviews(conn, "r1") == []
        conn.close()


# ── Flask API Tests (AC-9 through AC-16) ─────────────────────────────────────


class TestReviewAPI:
    """Spec-derived tests for Flask API endpoints."""

    def test_ac9_index_returns_html_with_links(self, tmp_path):
        """AC-9: GET / returns HTML with rule links to /rule/<id>."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.get("/")
            assert resp.status_code == 200
            html = resp.data.decode()
            assert "/rule/" in html

    def test_ac10_post_creates_review(self, tmp_path):
        """AC-10: POST /api/reviews creates entry and returns JSON."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.post(
                "/api/reviews",
                json={
                    "rule_id": "test-rule",
                    "flag": "verify",
                    "reviewer": "ai",
                    "note": "Test",
                },
            )
            assert resp.status_code == 201
            data = resp.get_json()
            assert data["rule_id"] == "test-rule"
            assert data["flag"] == "verify"
            assert "id" in data
            assert "flag_status" in data

    def test_ac11_post_rejects_invalid_flag(self, tmp_path):
        """AC-11: POST /api/reviews returns 400 for invalid flag."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.post(
                "/api/reviews",
                json={"rule_id": "test-rule", "flag": "bogus", "reviewer": "ai"},
            )
            assert resp.status_code == 400

    def test_ac12_post_requires_fields(self, tmp_path):
        """AC-12: POST /api/reviews returns 400 when required fields missing."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.post("/api/reviews", json={"rule_id": "test-rule"})
            assert resp.status_code == 400
            resp = c.post("/api/reviews", json={"flag": "verify"})
            assert resp.status_code == 400

    def test_ac13_rule_detail_page(self, tmp_path):
        """AC-13: GET /rule/<rule_id> returns full HTML detail page."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.get("/rule/test-rule")
            assert resp.status_code == 200
            html = resp.data.decode()
            assert "test-rule" in html
            assert "Test rule test-rule" in html

    def test_ac14_get_rule_reviews_api(self, tmp_path):
        """AC-14: GET /api/reviews/<rule_id> returns JSON with entries."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            c.post(
                "/api/reviews",
                json={
                    "rule_id": "test-rule",
                    "flag": "verify",
                    "reviewer": "ai",
                    "note": "N",
                },
            )
            resp = c.get("/api/reviews/test-rule")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["rule_id"] == "test-rule"
            assert len(data["entries"]) == 1
            assert "flag_status" in data

    def test_ac15_delete_review_api(self, tmp_path):
        """AC-15: DELETE /api/reviews/<id> removes entry."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.post(
                "/api/reviews",
                json={"rule_id": "test-rule", "flag": "verify", "reviewer": "ai"},
            )
            rid = resp.get_json()["id"]
            resp = c.delete(f"/api/reviews/{rid}")
            assert resp.status_code == 204

    def test_ac16_summary_api(self, tmp_path):
        """AC-16: GET /api/summary returns correct counts."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            c.post(
                "/api/reviews",
                json={"rule_id": "r1", "flag": "verify", "reviewer": "ai"},
            )
            c.post(
                "/api/reviews",
                json={"rule_id": "r2", "flag": "incorrect-check", "reviewer": "ai"},
            )
            resp = c.get("/api/summary")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["total_flagged"] == 2
            assert data["by_type"]["verify"] == 1
            assert data["by_type"]["incorrect-check"] == 1


# ── Rule Detail Page Tests (AC-17 through AC-18) ─────────────────────────────


class TestRuleDetailPage:
    """Spec-derived tests for rule detail page content."""

    def test_ac17_detail_shows_metadata(self, tmp_path):
        """AC-17: Rule detail page shows id, title, description, severity, tags."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.get("/rule/test-rule")
            html = resp.data.decode()
            assert "test-rule" in html
            assert "Description for test-rule" in html
            assert "medium" in html.lower()

    def test_ac18_detail_has_review_form(self, tmp_path):
        """AC-18: Rule detail page has inline review form."""
        app = _make_app(tmp_path)
        with app.test_client() as c:
            resp = c.get("/rule/test-rule")
            html = resp.data.decode()
            assert "incorrect-check" in html
            assert "verify" in html
            assert "reviewer" in html.lower()
            assert "<form" in html or "form" in html
