"""
IntentLock Reusable Decision Pattern — Drop-in for Strands Agents
==================================================================
Pattern:  #policy
Tags:     #strands-decider-2b  #policy

This file is the standalone, reusable asset for the hackathon.
Copy it into any Strands Agent project and wire it in as shown below.

WHAT IT DOES
------------
Before every tool call your agent proposes, IntentLock asks Strands Decider 2B
three batched `choice` questions in a single /v1/systemone request:

  provenance_verdict     trusted_operator | ungrounded_guess | untrusted_injection
  data_egress_policy     internal_scoped  | ambiguous_scope  | unauthorized_egress
  privilege_scope_check  within_authorized_scope | scope_expansion | privilege_escalation

The three answers feed a most-restrictive-wins mapping:

  untrusted_injection OR unauthorized_egress OR privilege_escalation  →  Deny
  scope_expansion                                                      →  Confirm
  ungrounded_guess                                                     →  Guide
  ambiguous_scope OR low confidence                                    →  Confirm
  trusted_operator + internal_scoped + within_authorized_scope        →  Proceed

A deterministic Stage 1 check runs first (RBAC, resource ownership, environment
allowlist, egress denylist, dry-run prerequisite) so the model is only invoked
when a hard rule does not already apply.

HOW TO USE IT IN YOUR OWN AGENT
--------------------------------
1.  Copy this file into your project (or import from intentlock.policy_engine).

2.  Create a ProvenanceContext with the immutable operator directive:

        ctx = ProvenanceContext(
            operator_id="your-operator-id",
            operator_roles={"operator"},
            trusted_operator_directive="The exact thing the operator asked for.",
            written_policy="Your policy text.",
            allowed_environments={"staging"},
            owned_resources={"resource-a", "resource-b"},
        )

3.  Start the local Decider server and build a client:

        # Terminal: strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 \\
        #               --device mps --port 8099
        client = LocalDeciderClient()

4.  Create the handler and pass it to your agent:

        handler = IntentLockPolicyHandler(client=client, context=ctx)
        agent = Agent(
            model=your_bedrock_model,
            tools=[your_tools],
            interventions=[handler],
        )

5.  Run the agent normally. The handler's before_tool_call intercepts every
    proposed tool call and returns Proceed / Guide / Deny / Confirm.

CUSTOMISATION NOTES
--------------------
- Adjust confidence_threshold (default 0.70) to trade false-blocks for
  false-allows. Measure on your own scenarios before choosing a threshold.
- Add destinations to denylisted_destinations in ProvenanceContext.
- Add tool names to resource_scoped_tools or environment_scoped_tools in
  _check_stage1_deterministic to extend hard enforcement.
- The dry-run prerequisite binds (operator_id, environment, resource_id,
  config_digest) and enforces a TTL. Call record_dry_run(..., succeeded=True)
  only from trusted infrastructure code after a real success result.

QUESTIONS SCHEMA (for direct /v1/systemone calls)
---------------------------------------------------
See INTENTLOCK_QUESTIONS below. You can send this dict directly to the Decider
server for your own batched inference calls.
"""

# Re-export from the canonical module for convenience.
from intentlock.policy_engine import (  # noqa: F401
    DEFAULT_CHECKPOINT,
    INTENTLOCK_QUESTIONS,
    IntentLockPolicyHandler,
    LocalDeciderClient,
    ProvenanceContext,
    compute_config_digest,
    safe_confidence,
    safe_probability,
)

# ---- Minimal standalone example ----

if __name__ == "__main__":
    import json
    from strands import Agent, tool
    from strands.models import BedrockModel

    @tool
    def get_resource_status(resource_id: str, environment: str) -> str:
        """Get the status of a resource. Args: resource_id, environment."""
        return json.dumps({"resource_id": resource_id, "environment": environment, "status": "ok"})

    ctx = ProvenanceContext(
        operator_id="example-operator",
        operator_roles={"operator"},
        trusted_operator_directive="Check the status of resource prod-db-1 in staging.",
        written_policy="Only access owned resources in allowed environments.",
        allowed_environments={"staging"},
        owned_resources={"prod-db-1"},
    )

    client = LocalDeciderClient()  # expects server on 127.0.0.1:8099

    handler = IntentLockPolicyHandler(client=client, context=ctx, confidence_threshold=0.70)

    model = BedrockModel(
        model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        region_name="us-east-1",
    )

    agent = Agent(
        model=model,
        tools=[get_resource_status],
        interventions=[handler],
    )

    result = agent("What is the status of prod-db-1 in staging?")
    print(result)

    print("\nAudit log:")
    for record in handler.audit_log:
        print(json.dumps(record, indent=2))
