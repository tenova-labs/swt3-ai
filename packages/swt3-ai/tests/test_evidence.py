"""SWT3 AI Witness SDK -- Evidence Bundle Exporter Tests."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from swt3_ai.exporters.evidence import EvidenceExporter


@pytest.fixture
def wal_dir(tmp_path):
    return str(tmp_path)


def write_wal_entries(wal_dir: str, tenant_id: str, entries: list) -> None:
    safe = tenant_id.replace("/", "_").replace("\\", "_")
    wal_path = Path(wal_dir) / f"{safe}.wal"
    content = "\n".join(json.dumps(e) for e in entries) + "\n"
    wal_path.write_text(content, encoding="utf-8")


class TestWatermarkTier:
    def test_demo_watermark_no_credentials(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        assert exp.build_bundle().metadata.watermark == "demo"

    def test_connected_watermark_with_api_key(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1", api_key="axm_test")
        assert exp.build_bundle().metadata.watermark == "connected"

    def test_sovereign_watermark_with_signing_and_hw(self, wal_dir):
        exp = EvidenceExporter(
            wal_dir=wal_dir, tenant_id="T1",
            signing_key="sk_test", has_hardware_attestation=True,
        )
        assert exp.build_bundle().metadata.watermark == "sovereign"

    def test_connected_not_sovereign_without_hw(self, wal_dir):
        exp = EvidenceExporter(
            wal_dir=wal_dir, tenant_id="T1",
            api_key="axm_test", signing_key="sk_test",
        )
        assert exp.build_bundle().metadata.watermark == "connected"


class TestWalReading:
    def test_empty_bundle_no_wal(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="NONEXISTENT")
        bundle = exp.build_bundle()
        assert len(bundle.anchors) == 0
        assert bundle.metadata.anchor_count == 0

    def test_reads_wal_entries(self, wal_dir):
        entries = [
            {"seq": 1, "fingerprint": "abc123", "payload": {
                "procedure_id": "AI-INF.1", "factor_a": 0.9, "factor_b": 100,
                "factor_c": 50, "anchor_epoch": 1, "fingerprint_timestamp_ms": 1000,
            }},
            {"seq": 2, "fingerprint": "def456", "payload": {
                "procedure_id": "AI-GRD.1", "factor_a": 1, "factor_b": 1,
                "factor_c": 1, "anchor_epoch": 2, "fingerprint_timestamp_ms": 2000,
            }},
        ]
        write_wal_entries(wal_dir, "T1", entries)
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        bundle = exp.build_bundle()
        assert len(bundle.anchors) == 2
        assert bundle.metadata.anchor_count == 2
        assert bundle.anchors[0].procedure_id == "AI-INF.1"
        assert bundle.anchors[1].procedure_id == "AI-GRD.1"

    def test_sorts_by_timestamp(self, wal_dir):
        entries = [
            {"seq": 1, "fingerprint": "a", "payload": {"procedure_id": "P2", "fingerprint_timestamp_ms": 5000}},
            {"seq": 2, "fingerprint": "b", "payload": {"procedure_id": "P1", "fingerprint_timestamp_ms": 1000}},
        ]
        write_wal_entries(wal_dir, "T1", entries)
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        bundle = exp.build_bundle()
        assert bundle.anchors[0].procedure_id == "P1"
        assert bundle.anchors[1].procedure_id == "P2"

    def test_skips_corrupted_lines(self, wal_dir):
        wal_path = Path(wal_dir) / "T1.wal"
        wal_path.write_text(
            '{"seq":1,"fingerprint":"ok","payload":{"procedure_id":"X"}}\n'
            'NOT JSON\n'
            '{"seq":2,"fingerprint":"ok2","payload":{"procedure_id":"Y"}}\n',
            encoding="utf-8",
        )
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        bundle = exp.build_bundle()
        assert len(bundle.anchors) == 2


class TestMerkleRoots:
    def test_includes_merkle_roots(self, wal_dir):
        roots = [{"root": "abcdef" * 10 + "ab", "count": 5, "timestamp": "2026-05-20T00:00:00Z"}]
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1", merkle_roots=roots)
        bundle = exp.build_bundle()
        assert len(bundle.merkle_roots) == 1
        assert bundle.merkle_roots[0]["count"] == 5


class TestMetadata:
    def test_populates_metadata(self, wal_dir):
        exp = EvidenceExporter(
            wal_dir=wal_dir, tenant_id="MY_TENANT",
            agent_id="agent-1", clearing_level=2,
        )
        bundle = exp.build_bundle()
        assert bundle.metadata.tenant_id == "MY_TENANT"
        assert bundle.metadata.agent_id == "agent-1"
        assert bundle.metadata.clearing_level == 2
        assert bundle.metadata.sdk_version == "0.5.3"
        assert "T" in bundle.metadata.generated_at
        assert bundle.metadata.export_timestamp > 0

    def test_defaults_unknown(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir)
        bundle = exp.build_bundle()
        assert bundle.metadata.tenant_id == "UNKNOWN"
        assert bundle.metadata.agent_id == "UNKNOWN"


class TestJsonExport:
    def test_valid_json_camel_case(self, wal_dir):
        entries = [{"seq": 1, "fingerprint": "fp1", "payload": {
            "procedure_id": "AI-INF.1", "factor_a": 1, "factor_b": 2,
            "factor_c": 3, "anchor_epoch": 1, "fingerprint_timestamp_ms": 1000,
        }}]
        write_wal_entries(wal_dir, "T1", entries)
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        parsed = json.loads(exp.export_json())
        assert parsed["metadata"]["tenantId"] == "T1"
        assert parsed["anchors"][0]["procedureId"] == "AI-INF.1"
        assert parsed["anchors"][0]["factorA"] == 1


class TestHtmlExport:
    def test_html_structure(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        html = exp.export_html()
        assert "<!DOCTYPE html>" in html
        assert "DEMO / UNVERIFIED" in html
        assert "SWT3 Evidence Bundle" in html

    def test_html_anchor_rows(self, wal_dir):
        entries = [{"seq": 1, "fingerprint": "fp_test", "payload": {
            "procedure_id": "AI-INF.1", "factor_a": 1, "factor_b": 0,
            "factor_c": 0, "anchor_epoch": 1, "fingerprint_timestamp_ms": 1000,
        }}]
        write_wal_entries(wal_dir, "T1", entries)
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1")
        html = exp.export_html()
        assert "AI-INF.1" in html
        assert "fp_test" in html

    def test_html_connected_watermark(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="T1", api_key="axm_test")
        html = exp.export_html()
        assert "CONNECTED" in html

    def test_html_escapes_entities(self, wal_dir):
        exp = EvidenceExporter(wal_dir=wal_dir, tenant_id="<script>alert(1)</script>")
        html = exp.export_html()
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
