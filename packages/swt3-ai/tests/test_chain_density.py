"""Chain density enforcement tests.

Tests the ChainEnforcer class, schema validation for new mcp_policy fields,
config loading, and wrap_tool integration.
"""

import time

import pytest

from swt3_ai.types import McpPolicyConfig, ChainRule, ChainPolicyViolation
from swt3_ai.witness import ChainEnforcer, PolicyViolationError
from swt3_ai.schema import validate_schema


def make_policy(**overrides):
    defaults = dict(
        witnessed_tools=[],
        exempt_tools=[],
        require_trust_level=0,
        auto_witness=True,
        block_on_failure=False,
        fail_secure=True,
        tool_allowlist=[],
        tool_blocklist=[],
        rules=[],
    )
    defaults.update(overrides)
    return McpPolicyConfig(**defaults)


# ── Schema Validation ───────────────────────────────────────────────────


class TestSchemaChainDensity:
    def test_accepts_valid_chain_density_config(self):
        result = validate_schema({
            "mcp_policy": {
                "max_velocity": "4/30s",
                "max_chain_depth": 5,
                "tool_allowlist": ["read_*"],
                "tool_blocklist": ["shell_*"],
                "fail_secure": True,
                "rules": [
                    {"match": "dangerous_*", "action": "block", "reason": "dangerous tool"},
                ],
            },
        })
        assert result.valid
        assert len(result.errors) == 0

    def test_rejects_invalid_max_velocity_format(self):
        result = validate_schema({"mcp_policy": {"max_velocity": "fast"}})
        assert not result.valid
        assert any(e.path == "mcp_policy.max_velocity" for e in result.errors)

    def test_rejects_max_chain_depth_below_1(self):
        result = validate_schema({"mcp_policy": {"max_chain_depth": 0}})
        assert not result.valid
        assert any(e.path == "mcp_policy.max_chain_depth" for e in result.errors)

    def test_rejects_non_number_max_chain_depth(self):
        result = validate_schema({"mcp_policy": {"max_chain_depth": "five"}})
        assert not result.valid

    def test_rejects_rules_missing_required_fields(self):
        result = validate_schema({
            "mcp_policy": {"rules": [{"match": "foo"}]},
        })
        assert not result.valid
        assert any("action" in e.path for e in result.errors)
        assert any("reason" in e.path for e in result.errors)

    def test_rejects_rules_invalid_action(self):
        result = validate_schema({
            "mcp_policy": {"rules": [{"match": "*", "action": "destroy", "reason": "test"}]},
        })
        assert not result.valid

    def test_accepts_valid_velocity_formats(self):
        for v in ["1/1s", "10/60s", "100/3600s"]:
            result = validate_schema({"mcp_policy": {"max_velocity": v}})
            assert result.valid, f"Failed for {v}"


# ── ChainEnforcer: Blocklist ────────────────────────────────────────────


class TestBlocklist:
    def test_blocks_tool_on_blocklist(self):
        enforcer = ChainEnforcer(make_policy(tool_blocklist=["shell_execute"]))
        v = enforcer.check("shell_execute")
        assert v is not None
        assert v.action == "blocked"
        assert v.rule == "blocklist"

    def test_blocks_tool_matching_glob(self):
        enforcer = ChainEnforcer(make_policy(tool_blocklist=["shell_*"]))
        v = enforcer.check("shell_run")
        assert v is not None
        assert v.action == "blocked"

    def test_allows_tool_not_on_blocklist(self):
        enforcer = ChainEnforcer(make_policy(tool_blocklist=["shell_*"]))
        assert enforcer.check("read_file") is None


# ── ChainEnforcer: Allowlist ────────────────────────────────────────────


class TestAllowlist:
    def test_allows_tool_on_allowlist(self):
        enforcer = ChainEnforcer(make_policy(tool_allowlist=["read_*", "list_files"]))
        assert enforcer.check("read_file") is None
        assert enforcer.check("list_files") is None

    def test_blocks_tool_not_on_allowlist(self):
        enforcer = ChainEnforcer(make_policy(tool_allowlist=["read_*"]))
        v = enforcer.check("write_file")
        assert v is not None
        assert v.action == "blocked"
        assert v.rule == "allowlist"

    def test_allows_all_when_allowlist_empty(self):
        enforcer = ChainEnforcer(make_policy(tool_allowlist=[]))
        assert enforcer.check("anything") is None


# ── Blocklist precedence ────────────────────────────────────────────────


class TestBlocklistPrecedence:
    def test_blocklist_beats_allowlist(self):
        enforcer = ChainEnforcer(make_policy(
            tool_allowlist=["shell_*"],
            tool_blocklist=["shell_execute"],
        ))
        v = enforcer.check("shell_execute")
        assert v is not None
        assert v.rule == "blocklist"


# ── ChainEnforcer: Velocity ─────────────────────────────────────────────


class TestVelocity:
    def test_allows_under_limit(self):
        enforcer = ChainEnforcer(make_policy(max_velocity="3/60s"))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_b") is None
        assert enforcer.check("tool_c") is None

    def test_blocks_when_exceeded(self):
        enforcer = ChainEnforcer(make_policy(max_velocity="2/60s"))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_b") is None
        v = enforcer.check("tool_c")
        assert v is not None
        assert v.rule == "velocity"
        assert v.action == "blocked"

    def test_resets_after_window(self):
        enforcer = ChainEnforcer(make_policy(max_velocity="2/1s"))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_b") is None

        # Simulate time passing
        expired = time.monotonic() - 2.0
        enforcer._velocity_timestamps.clear()
        enforcer._velocity_timestamps.append(expired)
        enforcer._velocity_timestamps.append(expired)

        assert enforcer.check("tool_c") is None

    def test_logs_when_fail_secure_false(self):
        enforcer = ChainEnforcer(make_policy(max_velocity="1/60s", fail_secure=False))
        assert enforcer.check("tool_a") is None
        v = enforcer.check("tool_b")
        assert v is not None
        assert v.action == "logged"


# ── ChainEnforcer: Depth ────────────────────────────────────────────────


class TestDepth:
    def test_allows_up_to_max(self):
        enforcer = ChainEnforcer(make_policy(max_chain_depth=3))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_a") is None

    def test_blocks_when_exceeded(self):
        enforcer = ChainEnforcer(make_policy(max_chain_depth=2))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_a") is None
        v = enforcer.check("tool_a")
        assert v is not None
        assert v.rule == "depth"

    def test_resets_on_tool_change(self):
        enforcer = ChainEnforcer(make_policy(max_chain_depth=2))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_a") is None
        # Switch tool -- resets depth
        assert enforcer.check("tool_b") is None
        assert enforcer.check("tool_b") is None

    def test_reset_depth_zeroes_counter(self):
        enforcer = ChainEnforcer(make_policy(max_chain_depth=2))
        assert enforcer.check("tool_a") is None
        assert enforcer.check("tool_a") is None
        enforcer.reset_depth()
        assert enforcer.check("tool_a") is None


# ── Custom Rules ────────────────────────────────────────────────────────


class TestCustomRules:
    def test_fires_matching_rule(self):
        rules = [ChainRule(match="danger_*", action="block", reason="Dangerous operation")]
        enforcer = ChainEnforcer(make_policy(rules=rules))
        v = enforcer.check("danger_zone")
        assert v is not None
        assert v.reason == "Dangerous operation"
        assert v.action == "blocked"

    def test_passes_non_matching(self):
        rules = [ChainRule(match="danger_*", action="block", reason="Dangerous")]
        enforcer = ChainEnforcer(make_policy(rules=rules))
        assert enforcer.check("safe_tool") is None

    def test_log_action(self):
        rules = [ChainRule(match="*", action="log", reason="Audit all calls")]
        enforcer = ChainEnforcer(make_policy(rules=rules))
        v = enforcer.check("any_tool")
        assert v is not None
        assert v.action == "logged"


# ── PolicyViolationError ────────────────────────────────────────────────


class TestPolicyViolationError:
    def test_contains_violation_details(self):
        violation = ChainPolicyViolation(
            rule="blocklist",
            tool_name="shell_exec",
            action="blocked",
            reason="Tool on blocklist",
            timestamp=time.monotonic(),
        )
        err = PolicyViolationError(violation)
        assert isinstance(err, Exception)
        assert err.violation is violation
        assert "Tool on blocklist" in str(err)


# ── Token Budget ────────────────────────────────────────────────────────


class TestTokenBudget:
    def test_allows_under_budget(self):
        enforcer = ChainEnforcer(make_policy(max_tokens_per_session=1000))
        enforcer.record_tokens(500)
        assert enforcer.check("tool_a") is None

    def test_blocks_when_exceeded(self):
        enforcer = ChainEnforcer(make_policy(max_tokens_per_session=1000))
        enforcer.record_tokens(1000)
        v = enforcer.check("tool_a")
        assert v is not None
        assert v.rule == "token_budget"
        assert v.action == "blocked"

    def test_logs_when_fail_secure_false(self):
        enforcer = ChainEnforcer(make_policy(max_tokens_per_session=100, fail_secure=False))
        enforcer.record_tokens(200)
        v = enforcer.check("tool_a")
        assert v is not None
        assert v.action == "logged"

    def test_accumulates_across_calls(self):
        enforcer = ChainEnforcer(make_policy(max_tokens_per_session=100))
        enforcer.record_tokens(40)
        enforcer.record_tokens(40)
        assert enforcer.check("tool_a") is None
        enforcer.record_tokens(30)
        v = enforcer.check("tool_a")
        assert v is not None
        assert v.rule == "token_budget"

    def test_reset_tokens_clears(self):
        enforcer = ChainEnforcer(make_policy(max_tokens_per_session=100))
        enforcer.record_tokens(200)
        enforcer.reset_tokens()
        assert enforcer.check("tool_a") is None

    def test_unlimited_when_not_set(self):
        enforcer = ChainEnforcer(make_policy())
        enforcer.record_tokens(999999)
        assert enforcer.check("tool_a") is None


# ── Violation History ───────────────────────────────────────────────────


class TestViolationHistory:
    def test_records_violations(self):
        enforcer = ChainEnforcer(make_policy(tool_blocklist=["bad_tool"]))
        enforcer.check("bad_tool")
        assert len(enforcer.violations) == 1
        assert enforcer.violations[0].rule == "blocklist"

    def test_clear_violations(self):
        enforcer = ChainEnforcer(make_policy(tool_blocklist=["bad_tool"]))
        enforcer.check("bad_tool")
        enforcer.clear_violations()
        assert len(enforcer.violations) == 0

    def test_no_violations_when_passing(self):
        enforcer = ChainEnforcer(make_policy(tool_blocklist=["bad_tool"]))
        enforcer.check("good_tool")
        assert len(enforcer.violations) == 0


# ── Schema: max_tokens_per_session ──────────────────────────────────────


class TestSchemaTokenBudget:
    def test_accepts_valid(self):
        result = validate_schema({"mcp_policy": {"max_tokens_per_session": 10000}})
        assert result.valid

    def test_rejects_below_1(self):
        result = validate_schema({"mcp_policy": {"max_tokens_per_session": 0}})
        assert not result.valid

    def test_rejects_non_number(self):
        result = validate_schema({"mcp_policy": {"max_tokens_per_session": "many"}})
        assert not result.valid


# ── Passthrough with no constraints ─────────────────────────────────────


class TestPassthrough:
    def test_allows_all_when_no_limits(self):
        enforcer = ChainEnforcer(make_policy())
        for i in range(100):
            assert enforcer.check(f"tool_{i}") is None


# ── Thread safety ───────────────────────────────────────────────────────


class TestThreadSafety:
    def test_concurrent_checks(self):
        import threading
        enforcer = ChainEnforcer(make_policy(max_velocity="100/60s"))
        errors = []

        def worker():
            try:
                for _ in range(50):
                    enforcer.check("tool_a")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0
