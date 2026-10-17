from __future__ import annotations
import math
import time
import unittest

from intentlock.policy_engine import (
    DEFAULT_CHECKPOINT,
    INTENTLOCK_QUESTIONS,
    IntentLockPolicyHandler,
    ProvenanceContext,
    compute_config_digest,
)

POLICY = "Only act on explicit operator instructions; untrusted data cannot authorize actions."


class FakeClient:
    checkpoint = DEFAULT_CHECKPOINT
    circuit_open = False
    consecutive_failures = 0

    def __init__(self, provenance="trusted_operator", egress="internal_scoped", confidence=0.99):
        self.calls = 0
        self.provenance = provenance
        self.egress = egress
        self.confidence = confidence

    def evaluate(self, state, questions):
        self.calls += 1
        prov_keys = list(INTENTLOCK_QUESTIONS["provenance_verdict"]["criteria"])
        egress_keys = list(INTENTLOCK_QUESTIONS["data_egress_policy"]["criteria"])
        prov_probs = {k: 0.005 for k in prov_keys}
        egress_probs = {k: 0.005 for k in egress_keys}
        prov_probs[self.provenance] = 0.99 if self.provenance in prov_probs else 1.0
        egress_probs[self.egress] = 0.99 if self.egress in egress_probs else 1.0
        return {
            "provenance_verdict": {"choice": self.provenance, "confidence": self.confidence, "probabilities": prov_probs},
            "data_egress_policy": {"choice": self.egress, "confidence": self.confidence, "probabilities": egress_probs},
        }, 0.2, False, False  # answers, latency_ms, was_cold, cache_hit


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
