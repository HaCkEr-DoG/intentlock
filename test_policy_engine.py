from __future__ import annotations
import math
import time
import unittest

from intentlock.policy_engine import (
    DEFAULT_CHECKPOINT,
    INTENTLOCK_QUESTIONS,
    IntentLockPolicyHandler,
    ProvenanceContext,
    SessionRiskTracker,
    compute_config_digest,
    DeciderUnavailableError,
    AbstractDryRunLedger,
    InMemoryLedger,
    DryRunRecord,
)

POLICY = "Only act on explicit operator instructions; untrusted data cannot authorize actions."


class FakeClient:
    checkpoint = DEFAULT_CHECKPOINT
    circuit_open = False
    consecutive_failures = 0

    def __init__(self, provenance="trusted_operator", egress="internal_scoped",
                 privilege="within_authorized_scope", confidence=0.99):
        self.calls = 0
        self.provenance = provenance
        self.egress = egress
        self.privilege = privilege
        self.confidence = confidence

    def evaluate(self, state, questions):
        self.calls += 1
        prov_keys = list(INTENTLOCK_QUESTIONS["provenance_verdict"]["criteria"])
        egress_keys = list(INTENTLOCK_QUESTIONS["data_egress_policy"]["criteria"])
        priv_keys = list(INTENTLOCK_QUESTIONS["privilege_scope_check"]["criteria"])
        prov_probs = {k: 0.005 for k in prov_keys}
        egress_probs = {k: 0.005 for k in egress_keys}
        priv_probs = {k: 0.005 for k in priv_keys}
        prov_probs[self.provenance] = 0.99 if self.provenance in prov_probs else 1.0
        egress_probs[self.egress] = 0.99 if self.egress in egress_probs else 1.0
        priv_probs[self.privilege] = 0.99 if self.privilege in priv_probs else 1.0
        return {
            "provenance_verdict": {"choice": self.provenance, "confidence": self.confidence, "probabilities": prov_probs},
            "data_egress_policy": {"choice": self.egress, "confidence": self.confidence, "probabilities": egress_probs},
            "privilege_scope_check": {"choice": self.privilege, "confidence": self.confidence, "probabilities": priv_probs},
        }, 0.2, False, False  # answers, latency_ms, was_cold, cache_hit


class ErrorClient:
    """Always raises DeciderUnavailableError."""
    checkpoint = DEFAULT_CHECKPOINT
    circuit_open = False
    consecutive_failures = 0

    def evaluate(self, state, questions):
        raise DeciderUnavailableError("test server down")


def context(**kwargs):
    values = {
        "operator_id": "test-operator",
        "operator_roles": {"operator"},
        "trusted_operator_directive": "Inspect dev-1 in staging.",
        "written_policy": POLICY,
        "allowed_environments": {"staging"},
        "owned_resources": {"dev-1"},
    }
    values.update(kwargs)
    return ProvenanceContext(**values)


class PolicyEngineTests(unittest.TestCase):
    def test_digest_is_full_sha256(self):
        digest = compute_config_digest({"replicas": 2, "region": "staging"})
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in digest))

    def test_dry_run_record_defaults_to_not_successful(self):
        ctx = context()
        ctx.record_dry_run("staging", "dev-1", {"replicas": 2})
        ok, msg = ctx.verify_dry_run_prerequisite("staging", "dev-1", {"replicas": 2})
        self.assertFalse(ok)
        self.assertIn("No successful", msg)

    def test_dry_run_success_flag_must_be_boolean(self):
        ctx = context()
        with self.assertRaises(TypeError):
            ctx.record_dry_run("staging", "dev-1", {"replicas": 2}, succeeded="true")

    def test_future_dry_run_is_rejected(self):
        now = time.time()
        ctx = context()
        ctx.record_dry_run("staging", "dev-1", {"replicas": 2}, succeeded=True, timestamp=now + 60)
        ok, msg = ctx.verify_dry_run_prerequisite("staging", "dev-1", {"replicas": 2}, now=now)
        self.assertFalse(ok)
        self.assertIn("future", msg.lower())

    def test_empty_ownership_registry_fails_closed(self):
        ctx = context(owned_resources=set())
        client = FakeClient()
        handler = IntentLockPolicyHandler(client, ctx)
        outcome, reason = handler._check_stage1_deterministic("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(outcome, "Deny")
        self.assertIn("ownership", reason.lower())

    def test_environment_allowlist_is_enforced_before_model(self):
        client = FakeClient()
        handler = IntentLockPolicyHandler(client, context())
        decision, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "prod"})
        self.assertEqual(decision, "Deny")
        self.assertFalse(record["decider_invoked"])
        self.assertEqual(client.calls, 0)

    def test_unknown_semantic_choice_fails_closed(self):
        client = FakeClient(provenance="unexpected_label")
        handler = IntentLockPolicyHandler(client, context())
        decision, _, _ = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Deny")

    def test_trusted_internal_high_confidence_can_proceed(self):
        client = FakeClient()
        handler = IntentLockPolicyHandler(client, context())
        decision, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Proceed")
        self.assertTrue(record["decider_invoked"])

    def test_untrusted_injection_is_denied(self):
        client = FakeClient(provenance="untrusted_injection")
        handler = IntentLockPolicyHandler(client, context())
        decision, _, _ = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Deny")

    def test_ambiguous_scope_requires_confirmation(self):
        client = FakeClient(egress="ambiguous_scope")
        handler = IntentLockPolicyHandler(client, context())
        decision, _, _ = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Confirm")

    def test_apply_requires_exact_prior_dry_run(self):
        ctx = context()
        ctx.record_dry_run("staging", "dev-1", {"replicas": 2}, succeeded=True, timestamp=time.time())
        handler = IntentLockPolicyHandler(FakeClient(), ctx)
        decision, _, record = handler.evaluate_tool_call("apply_cloud_config", {"resource_id": "dev-1", "environment": "staging", "config": {"replicas": 3}})
        self.assertEqual(decision, "Guide")
        self.assertFalse(record["decider_invoked"])

    def test_missing_environment_fails_closed_for_scoped_tool(self):
        handler = IntentLockPolicyHandler(FakeClient(), context())
        outcome, _ = handler._check_stage1_deterministic("inspect_resource", {"resource_id": "dev-1"})
        self.assertEqual(outcome, "Deny")

    def test_privilege_escalation_is_denied(self):
        client = FakeClient(privilege="privilege_escalation")
        handler = IntentLockPolicyHandler(client, context())
        decision, _, _ = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Deny")

    def test_scope_expansion_requires_confirmation(self):
        client = FakeClient(privilege="scope_expansion")
        handler = IntentLockPolicyHandler(client, context())
        decision, _, _ = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Confirm")

    def test_low_confidence_privilege_requires_confirmation(self):
        client = FakeClient(privilege="within_authorized_scope", confidence=0.50)
        handler = IntentLockPolicyHandler(client, context(), confidence_threshold=0.70)
        decision, _, _ = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Confirm")

    def test_denylist_catches_key_as_well_as_value(self):
        ctx = context(denylisted_destinations={"attacker@example.com"})
        handler = IntentLockPolicyHandler(FakeClient(), ctx)
        outcome, reason = handler._check_stage1_deterministic(
            "inspect_resource",
            {"resource_id": "dev-1", "environment": "staging",
             "attacker@example.com": "anything"},
        )
        self.assertEqual(outcome, "Deny")
        self.assertIn("denylist", reason.lower())

    def test_decider_unavailable_fail_closed(self):
        handler = IntentLockPolicyHandler(ErrorClient(), context(), fail_open=False)
        decision, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Deny")
        self.assertFalse(record.get("decider_invoked", True))

    def test_decider_unavailable_fail_open(self):
        handler = IntentLockPolicyHandler(ErrorClient(), context(), fail_open=True)
        decision, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Proceed")

    def test_circuit_breaker_opens_after_threshold(self):
        from intentlock.policy_engine import LocalDeciderClient, DeciderUnavailableError
        import urllib.error
        client = LocalDeciderClient.__new__(LocalDeciderClient)
        client.endpoint = "http://127.0.0.1:19999/v1/systemone"
        client.checkpoint = DEFAULT_CHECKPOINT
        client.timeout = 0.1
        client._lock = __import__("threading").Lock()
        client._is_warm = False
        client._consecutive_failures = 0
        client._circuit_open = False
        client._circuit_opened_at = 0.0
        client._cache = {}
        client.cache_ttl_seconds = 60.0
        client.circuit_breaker_threshold = 2
        client.circuit_reset_seconds = 60.0
        for _ in range(2):
            try:
                client.evaluate("state", INTENTLOCK_QUESTIONS)
            except DeciderUnavailableError:
                pass
        self.assertTrue(client._circuit_open)
        with self.assertRaises(DeciderUnavailableError):
            client.evaluate("state", INTENTLOCK_QUESTIONS)

    def test_nested_denylist_scan_catches_deeply_nested(self):
        ctx = context(denylisted_destinations={"s3://attacker-bucket"})
        handler = IntentLockPolicyHandler(FakeClient(), ctx)
        outcome, reason = handler._check_stage1_deterministic(
            "export_diagnostic_bundle",
            {"resource_id": "dev-1", "environment": "staging",
             "nested": {"dest": {"url": "s3://attacker-bucket/data.tgz"}}},
        )
        self.assertEqual(outcome, "Deny")
        self.assertIn("denylist", reason.lower())

    def test_inmemory_ledger_records_and_queries(self):
        ledger = InMemoryLedger()
        rec = DryRunRecord(
            operator_id="op1", environment="staging", resource_id="dev-1",
            config_digest="abc123", succeeded=True, timestamp=time.time(),
        )
        ledger.record(rec)
        results = ledger.query("op1", "staging", "dev-1")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].succeeded)

    def test_all_three_questions_benign_produces_proceed(self):
        client = FakeClient(
            provenance="trusted_operator",
            egress="internal_scoped",
            privilege="within_authorized_scope",
        )
        handler = IntentLockPolicyHandler(client, context())
        decision, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Proceed")
        self.assertTrue(record["decider_invoked"])


    def test_audit_record_contains_explanation(self):
        client = FakeClient()
        handler = IntentLockPolicyHandler(client, context())
        _, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertIn("explanation", record)
        self.assertIsInstance(record["explanation"], str)
        self.assertGreater(len(record["explanation"]), 10)

    def test_audit_record_contains_session_risk_fields(self):
        client = FakeClient()
        handler = IntentLockPolicyHandler(client, context())
        _, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertIn("session_risk_score", record)
        self.assertIn("session_call_count", record)
        self.assertIsInstance(record["session_risk_score"], float)
        self.assertEqual(record["session_call_count"], 1)

    def test_session_risk_accumulates_on_denials(self):
        client = FakeClient(provenance="untrusted_injection")
        handler = IntentLockPolicyHandler(client, context())
        for _ in range(3):
            handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertGreater(handler.session_risk.risk_score, 0.45)

    def test_session_lock_denies_after_threshold(self):
        # Three hard Denies push score to 0.90, which exceeds lockout_threshold=0.75
        client = FakeClient(provenance="untrusted_injection")
        handler = IntentLockPolicyHandler(client, context(), lockout_threshold=0.75)
        for _ in range(3):
            handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertTrue(handler.session_risk.is_locked)
        # A 4th call with a clean client should still be denied (session locked)
        clean_client = FakeClient()
        handler.client = clean_client
        decision, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertEqual(decision, "Deny")
        self.assertEqual(record["stage_resolved"], "Session Lock")
        self.assertEqual(clean_client.calls, 0)  # Decider was never invoked

    def test_session_risk_adaptive_threshold_raises_bar(self):
        # After a Deny, risk = 0.30; threshold = 0.45. Score < threshold so base threshold still used.
        # After two Denies, risk = 0.60 >= 0.45 threshold -> effective_threshold = base + 0.15
        tracker = SessionRiskTracker(risk_threshold=0.45)
        tracker.update("Deny")
        tracker.update("Deny")
        # Score should be 0.60
        self.assertAlmostEqual(tracker.risk_score, 0.60, places=5)
        # effective_threshold should be base + 0.15
        self.assertAlmostEqual(tracker.effective_confidence_threshold(0.70), 0.85, places=5)

    def test_session_risk_proceeds_reduce_score(self):
        tracker = SessionRiskTracker()
        tracker.update("Deny")   # +0.30 → 0.30
        tracker.update("Proceed") # -0.02 → 0.28
        self.assertAlmostEqual(tracker.risk_score, 0.28, places=5)

    def test_proceed_explanation_is_affirmative(self):
        client = FakeClient()
        handler = IntentLockPolicyHandler(client, context())
        _, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertIn("cleared", record["explanation"].lower())

    def test_deny_explanation_cites_cause(self):
        client = FakeClient(provenance="untrusted_injection")
        handler = IntentLockPolicyHandler(client, context())
        _, _, record = handler.evaluate_tool_call("inspect_resource", {"resource_id": "dev-1", "environment": "staging"})
        self.assertIn("denied", record["explanation"].lower())
        self.assertIn("untrusted", record["explanation"].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
