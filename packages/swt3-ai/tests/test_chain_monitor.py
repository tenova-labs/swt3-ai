"""Chain Monitor exporter tests."""

import json
import tempfile
from pathlib import Path

import pytest

from swt3_ai.exporters.chain_monitor import ChainMonitorExporter


def create_mock_wal(wal_dir: Path, tenant_id: str, entries: list) -> None:
    import re
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", tenant_id)
    wal_path = wal_dir / f"{safe}.wal"
    content = "\n".join(json.dumps(e) for e in entries) + "\n"
    wal_path.write_text(content, encoding="utf-8")


class TestChainMonitorExporter:
    def test_empty_report_no_wal(self, tmp_path):
        exporter = ChainMonitorExporter(wal_dir=str(tmp_path), tenant_id="TEST")
        report = exporter.build_report()
        assert len(report.timeline) == 0
        assert report.metadata.entry_count == 0

    def test_reads_wal_entries(self, tmp_path):
        create_mock_wal(tmp_path, "TEST", [
            {"seq": 1, "fingerprint": "abc123def456", "payload": {"procedure_id": "AI-INF.1", "fingerprint_timestamp_ms": 1700000000000}},
            {"seq": 2, "fingerprint": "def456abc789", "payload": {"procedure_id": "AI-TOOL.1", "fingerprint_timestamp_ms": 1700000001000, "ai_model_id": "search_db"}},
        ])
        exporter = ChainMonitorExporter(wal_dir=str(tmp_path), tenant_id="TEST")
        report = exporter.build_report()
        assert len(report.timeline) == 2
        assert report.timeline[0].procedure_id == "AI-INF.1"
        assert report.timeline[1].tool_name == "search_db"

    def test_flags_chain_enforcer_as_violation(self, tmp_path):
        create_mock_wal(tmp_path, "TEST", [
            {"seq": 1, "fingerprint": "abc123", "payload": {"procedure_id": "AI-CHAIN.1", "provider": "chain-enforcer", "fingerprint_timestamp_ms": 1700000000000}},
        ])
        exporter = ChainMonitorExporter(wal_dir=str(tmp_path), tenant_id="TEST")
        report = exporter.build_report()
        assert report.timeline[0].is_violation is True
        assert report.metadata.violation_count == 1

    def test_includes_passed_violations(self, tmp_path):
        exporter = ChainMonitorExporter(
            wal_dir=str(tmp_path),
            tenant_id="TEST",
            violations=[{"rule": "blocklist", "tool_name": "shell_exec", "action": "blocked", "reason": "Blocked"}],
        )
        report = exporter.build_report()
        assert len(report.violations) == 1
        assert report.metadata.violation_count == 1

    def test_export_json_valid(self, tmp_path):
        exporter = ChainMonitorExporter(wal_dir=str(tmp_path), tenant_id="TEST")
        result = json.loads(exporter.export_json())
        assert "metadata" in result
        assert "timeline" in result
        assert "violations" in result

    def test_export_html_contains_sections(self, tmp_path):
        create_mock_wal(tmp_path, "TEST", [
            {"seq": 1, "fingerprint": "abc123def456", "payload": {"procedure_id": "AI-INF.1", "fingerprint_timestamp_ms": 1700000000000}},
        ])
        exporter = ChainMonitorExporter(wal_dir=str(tmp_path), tenant_id="TEST", agent_id="agent-1")
        html = exporter.export_html()
        assert "SWT3 Exploit Chain Monitor" in html
        assert "Timeline" in html
        assert "Self-Signed / Unnotarized" in html
        assert "agent-1" in html
        assert "AI-INF.1" in html

    def test_export_html_merkle_root(self, tmp_path):
        exporter = ChainMonitorExporter(
            wal_dir=str(tmp_path),
            tenant_id="TEST",
            merkle_root="9f8e7d6c5b4a3f2e",
        )
        html = exporter.export_html()
        assert "Cryptographic Seal" in html
        assert "9f8e7d6c5b4a3f2e" in html

    def test_sorts_by_timestamp(self, tmp_path):
        create_mock_wal(tmp_path, "TEST", [
            {"seq": 2, "fingerprint": "late", "payload": {"procedure_id": "AI-TOOL.1", "fingerprint_timestamp_ms": 1700000002000}},
            {"seq": 1, "fingerprint": "early", "payload": {"procedure_id": "AI-INF.1", "fingerprint_timestamp_ms": 1700000001000}},
        ])
        exporter = ChainMonitorExporter(wal_dir=str(tmp_path), tenant_id="TEST")
        report = exporter.build_report()
        assert report.timeline[0].fingerprint == "early"
        assert report.timeline[1].fingerprint == "late"
