"""Tests for client-side chain verification (chain.py)."""

from swt3_ai.types import AnchorReference, ChainLink
from swt3_ai.chain import build_lookup, walk_chain, verify_chain_integrity


class TestBuildLookup:
    def test_builds_from_payloads(self):
        payloads = [
            {"anchor_fingerprint": "fp1", "references": [{"fingerprint": "fp2"}]},
            {"anchor_fingerprint": "fp2"},
        ]
        lookup = build_lookup(payloads)
        assert len(lookup) == 2
        assert len(lookup["fp1"]) == 1
        assert len(lookup["fp2"]) == 0

    def test_empty_payloads(self):
        lookup = build_lookup([])
        assert len(lookup) == 0

    def test_handles_anchor_reference_objects(self):
        payloads = [
            {"anchor_fingerprint": "fp1", "references": [AnchorReference(fingerprint="fp2")]},
        ]
        lookup = build_lookup(payloads)
        assert lookup["fp1"][0].fingerprint == "fp2"


class TestWalkChain:
    def test_linear_chain(self):
        lookup = {
            "A": [AnchorReference(fingerprint="B")],
            "B": [AnchorReference(fingerprint="C")],
            "C": [],
        }
        chain = walk_chain("A", lookup)
        assert len(chain.links) == 3
        assert chain.depth == 2
        assert chain.complete is True
        assert len(chain.gaps) == 0
        assert chain.truncated is False

    def test_branching_references(self):
        lookup = {
            "A": [AnchorReference(fingerprint="B"), AnchorReference(fingerprint="C")],
            "B": [],
            "C": [],
        }
        chain = walk_chain("A", lookup)
        assert len(chain.links) == 3
        assert chain.complete is True

    def test_gaps_when_reference_missing(self):
        lookup = {
            "A": [AnchorReference(fingerprint="B")],
        }
        chain = walk_chain("A", lookup)
        assert len(chain.links) == 1
        assert chain.gaps == ["B"]
        assert chain.complete is False

    def test_cycle_terminates(self):
        lookup = {
            "A": [AnchorReference(fingerprint="B")],
            "B": [AnchorReference(fingerprint="A")],
        }
        chain = walk_chain("A", lookup)
        assert len(chain.links) == 2
        assert chain.complete is True

    def test_truncates_at_max_depth(self):
        lookup = {}
        for i in range(20):
            lookup[f"n{i}"] = [AnchorReference(fingerprint=f"n{i + 1}")]
        lookup["n20"] = []

        chain = walk_chain("n0", lookup, max_depth=5)
        assert chain.truncated is True
        assert len(chain.links) <= 7

    def test_start_not_in_lookup(self):
        chain = walk_chain("missing", {})
        assert len(chain.links) == 0
        assert chain.gaps == ["missing"]
        assert chain.complete is False

    def test_deep_chain_within_limit(self):
        lookup = {}
        for i in range(5):
            lookup[f"n{i}"] = [AnchorReference(fingerprint=f"n{i + 1}")]
        lookup["n5"] = []
        chain = walk_chain("n0", lookup, max_depth=10)
        assert len(chain.links) == 6
        assert chain.truncated is False
        assert chain.complete is True

    def test_large_max_depth_short_chain(self):
        lookup = {"A": []}
        chain = walk_chain("A", lookup, max_depth=1000)
        assert len(chain.links) == 1


class TestVerifyChainIntegrity:
    def test_intact_chain(self):
        lookup = {
            "A": [AnchorReference(fingerprint="B")],
            "B": [],
        }
        chain = walk_chain("A", lookup)
        result = verify_chain_integrity(chain)
        assert result["intact"] is True
        assert len(result["issues"]) == 0

    def test_reports_gaps(self):
        lookup = {"A": [AnchorReference(fingerprint="B")]}
        chain = walk_chain("A", lookup)
        result = verify_chain_integrity(chain)
        assert result["intact"] is False
        assert any("not found" in issue for issue in result["issues"])

    def test_reports_truncation(self):
        lookup = {}
        for i in range(15):
            lookup[f"n{i}"] = [AnchorReference(fingerprint=f"n{i + 1}")]
        lookup["n15"] = []
        chain = walk_chain("n0", lookup, max_depth=3)
        result = verify_chain_integrity(chain)
        assert result["intact"] is False
        assert any("truncated" in issue for issue in result["issues"])

    def test_reports_empty_chain(self):
        chain = walk_chain("missing", {})
        result = verify_chain_integrity(chain)
        assert result["intact"] is False
        assert any("no resolved links" in issue for issue in result["issues"])
