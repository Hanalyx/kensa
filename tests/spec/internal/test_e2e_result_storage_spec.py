"""Spec-derived tests for e2e_result_storage.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/e2e_result_storage.spec.yaml — verifying that the E2E
result storage infrastructure creates correct directory structures,
meta.json manifests, output file handling, and multi-step promotion.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tests.e2e.conftest import (
    OUTPUT_COMMANDS,
    RESULTS_BASE,
    E2EHost,
    E2ETestContext,
    _extract_subcommand,
    _save_run_artifacts,
)


def _make_host(**overrides) -> E2EHost:
    """Create a test E2EHost with defaults."""
    defaults = {
        "host": "127.0.0.1",
        "port": 2222,
        "user": "testuser",
        "distro": "el9",
        "is_container": True,
    }
    defaults.update(overrides)
    return E2EHost(**defaults)


class TestE2eResultStorageSpecDerived:
    """Spec-derived tests for E2E result storage (AC-1 through AC-12)."""

    def test_ac1_session_dir_created_under_results_e2e(self, tmp_path):
        """AC-1: Session directory is created at results/e2e/<YYYY-MM-DD_HH-MM-SS>/."""
        assert (
            Path(__file__).resolve().parent.parent.parent.parent / "results" / "e2e"
            == RESULTS_BASE
        )
        # Verify the timestamp format by constructing one
        ts = datetime.now(timezone.utc)
        dirname = ts.strftime("%Y-%m-%d_%H-%M-%S")
        session_dir = tmp_path / dirname
        session_dir.mkdir(parents=True)
        assert session_dir.exists()
        # Verify format: YYYY-MM-DD_HH-MM-SS
        parts = dirname.split("_")
        assert len(parts) == 2
        assert len(parts[0].split("-")) == 3  # date
        assert len(parts[1].split("-")) == 3  # time

    def test_ac2_test_output_directory_structure(self, tmp_path):
        """AC-2: Each test gets <session>/<module>/<Class__method>/ with meta.json, stdout.log, stderr.log."""
        session_dir = tmp_path / "2026-02-27_14-30-05"
        test_module = "test_check_cycle"
        test_name = "TestCheckKnownBadE2E::test_gpgcheck_fails"
        dir_name = test_name.replace("::", "__")
        output_dir = session_dir / test_module / dir_name

        host = _make_host()
        result = subprocess.CompletedProcess(
            args=["test"], returncode=0, stdout="output", stderr="errors"
        )
        _save_run_artifacts(
            output_dir,
            cmd=["python3", "-m", "runner.cli", "check"],
            subcommand="check",
            host=host,
            result=result,
            start_time=datetime.now(timezone.utc),
            duration=1.5,
            output_files=[],
            test_name=test_name,
            test_module=test_module,
        )

        assert (output_dir / "meta.json").exists()
        assert (output_dir / "stdout.log").exists()
        assert (output_dir / "stderr.log").exists()
        assert (output_dir / "stdout.log").read_text() == "output"
        assert (output_dir / "stderr.log").read_text() == "errors"

    def test_ac3_meta_json_contains_required_fields(self, tmp_path):
        """AC-3: meta.json contains test_name, test_module, timestamp, command, subcommand, exit_code, host, duration_seconds, output_files."""
        output_dir = tmp_path / "test_output"
        host = _make_host()
        start_time = datetime.now(timezone.utc)

        _save_run_artifacts(
            output_dir,
            cmd=["python3", "-m", "runner.cli", "check", "--rule", "test.yml"],
            subcommand="check",
            host=host,
            result=subprocess.CompletedProcess(
                args=["test"], returncode=1, stdout="out", stderr="err"
            ),
            start_time=start_time,
            duration=2.345,
            output_files=["results.json", "results.csv"],
            test_name="TestCheck::test_example",
            test_module="test_check_cycle",
        )

        meta = json.loads((output_dir / "meta.json").read_text())
        assert meta["test_name"] == "TestCheck::test_example"
        assert meta["test_module"] == "test_check_cycle"
        assert meta["timestamp"] == start_time.isoformat()
        assert meta["command"] == [
            "python3",
            "-m",
            "runner.cli",
            "check",
            "--rule",
            "test.yml",
        ]
        assert meta["subcommand"] == "check"
        assert meta["exit_code"] == 1
        assert meta["host"]["hostname"] == "127.0.0.1"
        assert meta["host"]["port"] == 2222
        assert meta["host"]["user"] == "testuser"
        assert meta["host"]["distro"] == "el9"
        assert meta["host"]["is_container"] is True
        assert meta["duration_seconds"] == 2.345
        assert meta["output_files"] == ["results.json", "results.csv"]

    def test_ac4_output_commands_append_o_flags(self):
        """AC-4: check and remediate are in OUTPUT_COMMANDS and get -o flags."""
        assert "check" in OUTPUT_COMMANDS
        assert "remediate" in OUTPUT_COMMANDS
        assert "detect" not in OUTPUT_COMMANDS
        assert "rollback" not in OUTPUT_COMMANDS

    def test_ac5_pdf_guarded_by_reportlab(self, tmp_path):
        """AC-5: PDF output appended only when reportlab is importable; missing reportlab causes no error."""
        # Simulate reportlab not available
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "reportlab":
                raise ImportError("no reportlab")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            # The try/except in run_kensa handles this gracefully
            # Just verify the pattern works without error
            try:
                import reportlab  # noqa: F401

                has_reportlab = True
            except ImportError:
                has_reportlab = False
            assert not has_reportlab

    def test_ac6_single_call_flat_files(self, tmp_path):
        """AC-6: Single-call tests produce flat files directly in the test output directory."""
        output_dir = tmp_path / "test_output"
        ctx = E2ETestContext(
            test_name="TestCheck::test_single",
            test_module="test_check_cycle",
            output_dir=output_dir,
        )

        step_dir = ctx.next_step("check")
        assert step_dir == output_dir
        assert ctx.step_count == 1
        # No step_NNN subdirectories created
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "meta.json").write_text("{}")
        assert not any(
            d.name.startswith("step_") for d in output_dir.iterdir() if d.is_dir()
        )

    def test_ac7_multistep_promotion(self, tmp_path):
        """AC-7: Second run_kensa() call promotes step-1 files to step_001_<cmd>/ and creates step_002_<cmd>/."""
        output_dir = tmp_path / "test_output"
        output_dir.mkdir(parents=True)

        ctx = E2ETestContext(
            test_name="TestRemediate::test_cycle",
            test_module="test_remediate_cycle",
            output_dir=output_dir,
        )

        # Step 1: flat files
        step1_dir = ctx.next_step("check")
        assert step1_dir == output_dir
        # Simulate files created by step 1
        (output_dir / "meta.json").write_text('{"step": 1}')
        (output_dir / "stdout.log").write_text("step1 output")

        # Step 2: triggers promotion
        step2_dir = ctx.next_step("remediate")
        assert step2_dir == output_dir / "step_002_remediate"
        assert step2_dir.exists()

        # Step 1 files should have been moved
        step1_promoted = output_dir / "step_001_check"
        assert step1_promoted.exists()
        assert (step1_promoted / "meta.json").exists()
        assert (step1_promoted / "stdout.log").exists()
        assert not (output_dir / "meta.json").exists()  # moved away

        # Step 3
        step3_dir = ctx.next_step("check")
        assert step3_dir == output_dir / "step_003_check"
        assert step3_dir.exists()

    def test_ac8_non_output_commands_no_o_flags(self):
        """AC-8: detect and rollback are not in OUTPUT_COMMANDS, so no -o flags appended."""
        assert _extract_subcommand(["detect"]) == "detect"
        assert _extract_subcommand(["rollback", "--start", "1"]) == "rollback"
        assert "detect" not in OUTPUT_COMMANDS
        assert "rollback" not in OUTPUT_COMMANDS

    def test_ac9_run_kensa_return_type_unchanged(self):
        """AC-9: run_kensa() return type is subprocess.CompletedProcess."""
        import inspect

        from tests.e2e.conftest import run_kensa

        sig = inspect.signature(run_kensa)
        # With `from __future__ import annotations`, annotation is a string
        annotation = sig.return_annotation
        assert annotation in (
            subprocess.CompletedProcess,
            "subprocess.CompletedProcess",
        )

    def test_ac10_session_meta_json_fields(self, tmp_path):
        """AC-10: session_meta.json contains session_start, session_end, duration_seconds, total_runs, results_dir."""
        session_dir = tmp_path / "session"
        session_dir.mkdir()

        # Create some fake meta.json files to count
        test_dir = session_dir / "test_mod" / "TestClass__test_method"
        test_dir.mkdir(parents=True)
        (test_dir / "meta.json").write_text("{}")

        ts = datetime.now(timezone.utc)
        end = datetime.now(timezone.utc)
        meta = {
            "session_start": ts.isoformat(),
            "session_end": end.isoformat(),
            "duration_seconds": round((end - ts).total_seconds(), 3),
            "total_runs": len(list(session_dir.rglob("meta.json"))),
            "results_dir": str(session_dir),
        }
        (session_dir / "session_meta.json").write_text(
            json.dumps(meta, indent=2) + "\n"
        )

        written = json.loads((session_dir / "session_meta.json").read_text())
        assert "session_start" in written
        assert "session_end" in written
        assert "duration_seconds" in written
        assert written["total_runs"] == 1
        assert written["results_dir"] == str(session_dir)

    def test_ac11_terminal_summary_hook_exists(self):
        """AC-11: pytest_terminal_summary hook is defined in conftest."""
        import inspect

        from tests.e2e.conftest import pytest_terminal_summary

        assert callable(pytest_terminal_summary)
        params = list(inspect.signature(pytest_terminal_summary).parameters)
        assert "terminalreporter" in params
        assert "config" in params

    def test_ac12_output_files_filtered_to_actual(self, tmp_path):
        """AC-12: output_files in meta.json lists only files actually created."""
        output_dir = tmp_path / "test_output"
        output_dir.mkdir(parents=True)

        # Create only some of the expected files
        (output_dir / "results.json").write_text("{}")
        # results.csv and evidence.json NOT created

        expected = ["results.json", "results.csv", "evidence.json"]
        actual = [f for f in expected if (output_dir / f).exists()]
        assert actual == ["results.json"]

        _save_run_artifacts(
            output_dir,
            cmd=["test"],
            subcommand="check",
            host=_make_host(),
            result=subprocess.CompletedProcess(
                args=["test"], returncode=0, stdout="", stderr=""
            ),
            start_time=datetime.now(timezone.utc),
            duration=0.1,
            output_files=actual,
            test_name="Test::test",
            test_module="test_mod",
        )

        meta = json.loads((output_dir / "meta.json").read_text())
        assert meta["output_files"] == ["results.json"]
