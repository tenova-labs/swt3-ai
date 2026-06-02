"""Tests for swt3 doctor CLI."""

import os
from pathlib import Path

import pytest

from swt3_ai.doctor import run_doctor_checks


def _write_yaml(tmp_path: Path, content: str) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "swt3.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


class TestDoctor:
    def test_all_checks_pass_valid_config(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "api_key: axm_test\ntenant_id: TEST\nclearing_level: 1\n")
        checks = run_doctor_checks(path)
        fails = [c for c in checks if c.status == "fail"]
        assert len(fails) == 0
        assert len(checks) >= 5

    def test_yaml_not_found(self, tmp_path: Path) -> None:
        checks = run_doctor_checks(str(tmp_path / "nonexistent.yaml"))
        assert len(checks) >= 1

    def test_invalid_yaml_syntax(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "{{{invalid yaml")
        checks = run_doctor_checks(path)
        yaml_check = next(c for c in checks if c.name == "YAML syntax")
        assert yaml_check.status == "fail"

    def test_missing_env_var(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("SWT3_NONEXISTENT_VAR_TEST", raising=False)
        path = _write_yaml(tmp_path, "api_key_env: SWT3_NONEXISTENT_VAR_TEST\ntenant_id: TEST\n")
        checks = run_doctor_checks(path)
        env_check = next(c for c in checks if c.name == "Environment")
        assert env_check.status == "warn"
        assert "SWT3_NONEXISTENT_VAR_TEST" in env_check.message

    def test_invalid_profile(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "api_key: axm_test\ntenant_id: TEST\nprofile: bogus-profile\n")
        checks = run_doctor_checks(path)
        profile_check = next(c for c in checks if c.name == "Profile")
        assert profile_check.status == "fail"

    def test_unknown_section_key(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, """
api_key: axm_test
tenant_id: TEST
trust_mesh:
  mode: strict
  bogus_key: true
""")
        checks = run_doctor_checks(path)
        sections_check = next(c for c in checks if c.name == "Sections")
        assert sections_check.status == "fail"

    def test_tpm_check_returns_pass_or_warn(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "api_key: axm_test\ntenant_id: TEST\n")
        checks = run_doctor_checks(path)
        hw_check = next(c for c in checks if c.name == "Hardware")
        assert hw_check.status in ("pass", "warn")

    def test_correct_total_check_count(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path, "api_key: axm_test\ntenant_id: TEST\n")
        checks = run_doctor_checks(path)
        assert len(checks) == 9

    def test_ci_mode_plain_text_no_ansi(self, tmp_path: Path, capsys) -> None:
        from swt3_ai.doctor import print_doctor_results
        path = _write_yaml(tmp_path, "api_key: axm_test\ntenant_id: TEST\n")
        checks = run_doctor_checks(path)
        print_doctor_results(checks, ci_mode=True)
        output = capsys.readouterr().out
        assert "\033[" not in output
        assert "swt3-doctor:" in output
        assert "checks," in output

    def test_ci_mode_reports_warn_count(self, tmp_path: Path, capsys, monkeypatch) -> None:
        from swt3_ai.doctor import print_doctor_results
        monkeypatch.delenv("SWT3_MISSING_CI_TEST", raising=False)
        path = _write_yaml(tmp_path, "api_key_env: SWT3_MISSING_CI_TEST\ntenant_id: TEST\n")
        checks = run_doctor_checks(path)
        print_doctor_results(checks, ci_mode=True)
        output = capsys.readouterr().out
        lines = output.strip().split("\n")
        summary = [l for l in lines if l.startswith("swt3-doctor:")]
        assert len(summary) == 1
        assert "warn" in summary[0]
