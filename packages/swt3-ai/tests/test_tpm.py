"""TPM 2.0 Attestation Tests (AI-HW.3)."""

import json
from unittest.mock import patch

import pytest

from swt3_ai.hardware import parse_tpm_pcr_output, ZERO_PCR_HASH, query_tpm
from swt3_ai.types import TPMSnapshot, PcrRegister
from swt3_ai.fingerprint import sha256_truncated
from swt3_ai import Witness


# ── Fixtures ──────────────────────────────────────────────────────────

RAW_PCR_0 = "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
RAW_PCR_7 = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
ZERO_PCR_RAW = "0" * 64

MOCK_PCRREAD_OUTPUT = f"""sha256:
  0 : 0x{RAW_PCR_0}
  7 : 0x{RAW_PCR_7}
"""

MOCK_PCRREAD_WITH_ZERO = f"""sha256:
  0 : 0x{RAW_PCR_0}
  7 : 0x{ZERO_PCR_RAW}
"""


def mk_tpm_snapshot(pcr_count: int, include_zero: bool = False) -> TPMSnapshot:
    pcrs = [
        PcrRegister(
            index=i,
            bank="sha256",
            digest_hash=ZERO_PCR_HASH if (include_zero and i == pcr_count - 1) else f"pcrhash{i}",
        )
        for i in range(pcr_count)
    ]
    return TPMSnapshot(
        available=pcr_count > 0,
        manufacturer="mfghash",
        firmware_version="fwhash",
        pcrs=pcrs,
        endorsement_key_hash="ekhash",
        hostname_hash="hosthash",
    )


def mk_witness(**overrides):
    defaults = dict(
        endpoint="https://test.example.com",
        api_key="axm_test_key",
        tenant_id="test_tenant",
    )
    defaults.update(overrides)
    return Witness(**defaults)


# ── parse_tpm_pcr_output ──────────────────────────────────────────────

class TestParsePcrOutput:
    def test_parses_standard_output(self):
        pcrs = parse_tpm_pcr_output(MOCK_PCRREAD_OUTPUT)
        assert len(pcrs) == 2
        assert pcrs[0].index == 0
        assert pcrs[0].bank == "sha256"
        assert pcrs[1].index == 7

    def test_hashes_raw_values(self):
        pcrs = parse_tpm_pcr_output(MOCK_PCRREAD_OUTPUT)
        assert pcrs[0].digest_hash != RAW_PCR_0
        assert pcrs[0].digest_hash == sha256_truncated(RAW_PCR_0)

    def test_empty_input(self):
        assert parse_tpm_pcr_output("") == []

    def test_malformed_lines_skipped(self):
        output = f"sha256:\n  0 : 0x{RAW_PCR_0}\n  garbage\n  7 : 0x{RAW_PCR_7}\n"
        pcrs = parse_tpm_pcr_output(output)
        assert len(pcrs) == 2


# ── ZERO_PCR_HASH ─────────────────────────────────────────────────────

class TestZeroPcrHash:
    def test_is_hash_of_64_zeros(self):
        assert ZERO_PCR_HASH == sha256_truncated("0" * 64)

    def test_differs_from_real_pcr(self):
        assert ZERO_PCR_HASH != sha256_truncated(RAW_PCR_0)


# ── witness_tpm_attestation ───────────────────────────────────────────

class TestWitnessTPM:
    def test_procedure_id(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert p.procedure_id == "AI-HW.3"

    def test_factor_a_is_pcr_count(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert p.factor_a == 8.0

    def test_factor_b_healthy(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert p.factor_b == 1.0

    def test_factor_b_zero_pcr(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(2, include_zero=True))
        assert p.factor_b == 0.0

    def test_factor_b_no_tpm(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(0))
        assert p.factor_a == 0.0
        assert p.factor_b == 0.0

    def test_factor_c_reserved(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert p.factor_c == 0.0

    def test_clearing_0_has_context(self):
        w = mk_witness(clearing_level=0)
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(2))
        assert p.ai_context is not None
        assert p.ai_context["provider"] == "tpm-2.0"
        assert p.ai_context["pcr_count"] == 2

    def test_clearing_1_has_context(self):
        w = mk_witness(clearing_level=1)
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(2))
        assert p.ai_context is not None

    def test_clearing_2_strips_context(self):
        w = mk_witness(clearing_level=2)
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert p.ai_context is None

    def test_clearing_3_strips_context(self):
        w = mk_witness(clearing_level=3)
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert p.ai_context is None

    def test_fingerprint_format(self):
        w = mk_witness()
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        assert len(p.anchor_fingerprint) == 12
        assert all(c in "0123456789abcdef" for c in p.anchor_fingerprint)

    def test_agent_id_survives(self):
        w = mk_witness(agent_id="agent-x")
        p = w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(2))
        assert p.agent_id == "agent-x"


# ── Trust credential ─────────────────────────────────────────────────

class TestTrustCredentialTPM:
    def test_hw3_alone_sets_attestation(self):
        w = mk_witness(signing_key="sk")
        w.witness_tpm_attestation(snapshot=mk_tpm_snapshot(8))
        cred = w.present_credential()
        assert cred.has_hardware_attestation is True

    def test_neither_hw_no_attestation(self):
        w = mk_witness(signing_key="sk")
        cred = w.present_credential()
        assert cred.has_hardware_attestation is False


# ── Security ──────────────────────────────────────────────────────────

class TestTPMSecurity:
    def test_raw_pcr_never_in_payload(self):
        w = mk_witness(clearing_level=0)
        snapshot = TPMSnapshot(
            available=True,
            manufacturer=sha256_truncated("INTC"),
            firmware_version=sha256_truncated("7.2.0"),
            pcrs=[
                PcrRegister(index=0, bank="sha256", digest_hash=sha256_truncated(RAW_PCR_0)),
                PcrRegister(index=7, bank="sha256", digest_hash=sha256_truncated(RAW_PCR_7)),
            ],
            endorsement_key_hash=sha256_truncated("ek-pub-key-data"),
            hostname_hash=sha256_truncated("myhost"),
        )
        p = w.witness_tpm_attestation(snapshot=snapshot)
        payload_json = json.dumps(p.__dict__, default=str)

        assert RAW_PCR_0 not in payload_json
        assert RAW_PCR_7 not in payload_json
        assert "INTC" not in payload_json
        assert "ek-pub-key-data" not in payload_json
        assert "myhost" not in payload_json
