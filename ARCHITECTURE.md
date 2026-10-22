# IntentLock Architecture

**Version:** `2026.10.10`  
**Model:** `StrandsAgents/strands-decider-2B-qwen3.5-v1-2610`  
**Entry point:** `intentlock/policy_engine.py`

---

## Overview

IntentLock is a provenance-aware temporal policy engine that intercepts every tool call proposed by an agentic InfraOps workflow. Before any infrastructure operation executes, it asks **four orthogonal policy questions** in a single batched Strands Decider 2B request and maps the answers to one of four typed actions.

```
Agent proposes tool call
        │
        ▼
┌───────────────────────────────────────────────────────┐
│  IntentLockPolicyHandler.evaluate_tool_call()         │
│                                                       │
│   Session Lock check                                  │
│        │                                              │
│   Velocity tracking                                   │
│        │                                              │
│   Stage 0 ── Injection regex scan (< 0.01 ms)        │
│        │                                              │
│   Stage 1 ── Deterministic fast-fail (< 0.1 ms)      │
│        │                                              │
│   Stage 2 ── Strands Decider 2B (~1890 ms warm)       │
│        │                                              │
│   Stage 3 ── Most-restrictive-wins action mapping     │
│        │                                              │
│   Audit log append                                    │
└───────────────────────────────────────────────────────┘
        │
        ▼
  Proceed / Confirm / Guide / Deny
```

**Fail-closed by default.** `Proceed` requires four explicit clean answers at sufficient confidence. Unknown model output, malformed distributions, confidence 0.0, or server timeout all produce `Deny`.

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  Operator                                                       │
│   ├─ trusted_operator_directive  (immutable string)            │
│   ├─ operator_id / operator_roles                              │
│   ├─ allowed_environments  {staging, prod}                     │
│   ├─ owned_resources  {web-1, ...}                             │
│   ├─ denylisted_destinations                                   │
│   ├─ sensitive_parameters                                      │
│   └─ untrusted_external_data  [{source, content}, ...]        │
└────────────────────────────┬────────────────────────────────────┘
                             │  ProvenanceContext
                             ▼
                  IntentLockPolicyHandler
                             │
         ┌───────────────────┼──────────────────────┐
         │                   │                      │
         ▼                   ▼                      ▼
   Session Lock        _approved_value_pool    session_risk
   (0.75 lockout)      (token set of all       (SessionRiskTracker)
                       approved call args)
         │
         ▼
   evaluate_tool_call(tool_name, tool_args)
         │
         ├──[Stage 0]──> _scan_untrusted_for_injection()
         │                   └─> 12 _INJECTION_PATTERNS
         │
         ├──[Stage 1]──> _check_stage1_deterministic()
         │                   ├─> denylist scan (recursive)
         │                   ├─> sensitive parameter guard
         │                   ├─> RBAC (delete_resource needs admin)
         │                   ├─> environment allowlist
         │                   ├─> resource ownership (fail-closed)
         │                   └─> dry-run prerequisite (apply_cloud_config)
         │
         ├──[Provenance]──> _trace_argument_values()
         │                   └─> 3-tier classification per string arg
         │
         ├──[Envelope]──> build_provenance_envelope()
         │                   └─> 6-section structured string
         │
         ├──[Stage 2]──> LocalDeciderClient.evaluate()
         │                   └─> /v1/systemone batched request
         │                       └─> 4 questions → answers + probs
         │
         └──[Stage 3]──> most-restrictive-wins mapping
                             └─> Proceed / Confirm / Guide / Deny
```

---

## Stage 0: Injection Regex Scan

**File:** `policy_engine.py:73–86`  
**Latency:** < 0.01 ms

Twelve pre-compiled `_INJECTION_PATTERNS` scan the `untrusted_external_data` field of `ProvenanceContext` before any other processing:

| Pattern | What it catches |
|---|---|
| `SYSTEM:` / `SYSTEM OVERRIDE:` | Classic injection preambles |
| `Ignore (all )?previous instructions` | LLM instruction-override phrase |
| `Your (new )?task is` | Task-substitution injection |
| `\bDAN\b` | Do-Anything-Now jailbreak |
| `\bACT AS\b` | Role-substitution attempt |
| `Disregard (your )?guidelines` | Safety-bypass phrase |
| `You are now` | Persona injection |
| `Forget (everything\|all)` | Memory-wipe instruction |
| `New (directive\|objective\|primary goal)` | Objective substitution |
| `Override (safety\|policy\|guidelines\|instructions)` | Explicit override request |
| `CONFIDENTIAL:` / `SECRET:` | Social-engineering preambles |
| `Execute immediately` | Urgency-pressure injection |

Any match is a `hit`. Hits pre-bump the session risk score (`Confirm` delta = +0.12) before Decider evaluates the specific call. Two Stage 0 hits, or one hit combined with a soft Decider injection signal, escalates the outcome to `Deny`.

---

## Stage 1: Deterministic Fast-Fail

**File:** `policy_engine.py:1182–1267`  
**Latency:** < 0.1 ms

Hard rules that require no model inference. Executed in order:

### 1. Denylist scan
`_scan_for_denylist()` recursively walks all tool argument values (dict, list, str) up to depth 6. Any value matching a `denylisted_destination` string (case-insensitive) produces an immediate `Deny`.

### 2. Sensitive parameter guard
If any argument key appears in `context.sensitive_parameters`, produces `Confirm` before model evaluation. Operator must explicitly acknowledge.

### 3. RBAC
`delete_resource` requires `"admin"` in `operator_roles`. Any other role set produces `Deny`.

### 4. Environment allowlist
All environment-scoped tools (`inspect_resource`, `dry_run_config`, `apply_cloud_config`, `delete_resource`, `set_key`) require a non-empty `environment` arg. The value must be in `allowed_environments`. Staging-only operators cannot touch prod.

Conflicting `environment` / `env` arguments in the same call produce `Deny`.

### 5. Resource ownership (fail-closed)
Resource-scoped tools require a non-empty `resource_id` that appears in `owned_resources`. **Empty registry = deny-all.** This is a deliberate design choice: an uninitialized set is not blanket permission.

### 6. Dry-run prerequisite
`apply_cloud_config` is blocked unless a matching `dry_run_config` was recorded via `InMemoryLedger` with:
- Same environment
- Same resource_id
- SHA-256 digest of the `config` dict matching the stored digest
- Within `dry_run_ttl_seconds` (default 300 s)

If the prerequisite fails, the outcome is `Guide` (not `Deny`), giving the agent a chance to run the dry-run first. The `_apply_bounded_guide()` method enforces a retry budget (`max_guide_retries = 1`); budget exhaustion upgrades to `Deny`.

---

## Stage 2: Strands Decider 2B

**File:** `policy_engine.py:428–540` (client), `1108–1160` (envelope builder)  
**Latency:** ~1890 ms warm / p95 ~2257 ms (M4 MPS)

### 2a. Three-Tier Value Provenance

Before building the envelope, `_trace_argument_values()` classifies every string argument value:

| Tier | Criterion | Trust |
|---|---|---|
| `operator-referenced` | ≥ 50% token overlap with `trusted_operator_directive` | Highest |
| `session-derived` | Novel vs. directive, but ≥ 50% tokens in `_approved_value_pool` | Medium |
| `unverified-novel` | No lineage in directive or approved session history | Lowest — injection target |

Tokenization: split on `r'\s+'`, lowercase. The `_approved_value_pool` grows only on `Proceed`, `Guide`, or `Confirm` outcomes — never on `Deny`. A resource ID first seen in an approved `list_resources` call becomes `session-derived` on next use.

### 2b. Provenance Envelope

`build_provenance_envelope()` assembles a structured string in a **deliberate** 6-section order:

```
[PROPOSED TOOL CALL]
  tool_name(arg=value, ...)

[ARGUMENT VALUE TRACING]
  arg1: "value1" → tier=operator-referenced
  arg2: "value2" → tier=unverified-novel

[TRUSTED OPERATOR DIRECTIVE]
  Operator ID: ...
  Operator Roles: [...]
  Authorized Environments: [...]
  Authorized Resources: [...]
  Directive: <verbatim text>

[SESSION HISTORY (last N of M calls)]
  1. tool_name → Proceed | provenance=trusted_operator | egress=internal_scoped
  ...

[UNTRUSTED EXTERNAL DATA]
  source=incident-log: <content>
  ...

[WRITTEN POLICY]
  <verbatim policy text>
```

The order is deliberate: the proposed action and its value provenance appear **before** the directive, not after. On a 2B model, context orientation matters — the model sees what it must decide about first.

### 2c. The Four Policy Questions

Sent as a single batched `/v1/systemone` request:

| ID | Dimension | Choices | What it catches |
|---|---|---|---|
| `provenance_verdict` | Call source | `trusted_operator` / `ungrounded_guess` / `untrusted_injection` | Did args come from the operator or were they injected? |
| `data_egress_policy` | Call destination | `internal_scoped` / `ambiguous_scope` / `unauthorized_egress` | Is the operation staying in scope? |
| `privilege_scope_check` | Capabilities | `within_authorized_scope` / `scope_expansion` / `privilege_escalation` | Is the call within authorized powers? |
| `argument_value_alignment` | Value lineage | `yes` / `no` | Can every arg value be traced to a verified source? |

Each answer block includes: `choice` (argmax label), `confidence` (float), `probabilities` (full distribution over choices).

**Confidence threshold:** `confidence_threshold = 0.70`. Answers below this threshold are treated as uncertain and escalate the outcome.

### 2d. Soft-Signal Detection

IntentLock reads the raw probability distribution, not just the argmax:

- `p(untrusted_injection) > 0.30` fires a soft injection signal even when argmax is `trusted_operator`
- `p(unauthorized_egress) > 0.30` (via `p_egress_bad`) fires a soft egress signal

Two soft signals, or one combined with a Stage 0 hit, can escalate to `Deny`.

### 2e. LocalDeciderClient

**File:** `policy_engine.py:428–540`

| Parameter | Default | Description |
|---|---|---|
| `endpoint` | `http://127.0.0.1:8099/v1/systemone` | Decider server URL |
| `circuit_breaker_threshold` | 3 | Consecutive failures before circuit opens |
| `circuit_reset_seconds` | 60 | Time before circuit closes again |
| `cache_ttl_seconds` | 60 | Response cache TTL (SHA-256 keyed on envelope) |

Circuit breaker: 3 consecutive Decider failures → circuit opens → all requests fail-closed (`Deny`) for 60 s. Prevents cascading latency under a downed model server.

Response cache: identical envelope + same questions → cached answer returned. TTL 60 s. Prevents redundant inference on repeated identical calls.

---

## Stage 3: Most-Restrictive-Wins Mapping

**File:** `policy_engine.py:1595–1660` (composite score), `1662–1706` (explanation)

```
Any of:
  provenance_verdict = untrusted_injection          →  Deny
  data_egress_policy = unauthorized_egress          →  Deny
  privilege_scope_check = privilege_escalation      →  Deny
  argument_value_alignment = no  (high confidence)  →  Guide / Deny

Any of:
  privilege_scope_check = scope_expansion           →  Confirm
  provenance_verdict = ungrounded_guess             →  Confirm
  data_egress_policy = ambiguous_scope              →  Confirm
  confidence < 0.70 on any answer                  →  Confirm

All four clear + all confidence ≥ 0.70             →  Proceed
```

`Proceed` is never a default — it requires four explicit clean answers with sufficient confidence.

### Composite Threat Score

A `composite_threat_score` (0–1 float) is computed per call and written to the audit log:

| Component | Weight | Trigger |
|---|---|---|
| Injection pre-scan | 0.25 | Binary: any Stage 0 hit |
| Provenance choice | 0–0.30 | Max at `untrusted_injection` |
| Soft injection prob | 0–0.15 | `p_injection` when not top choice |
| Egress choice | 0–0.30 | Max at `unauthorized_egress` |
| Soft egress prob | 0–0.10 | `p_egress_bad` when not top choice |
| Privilege choice | 0–0.25 | Max at `privilege_escalation` |
| Arg value misalignment | 0–0.20 | `argument_value_alignment = no` |
| Session risk bleed | 0–0.15 | Scaled `session_risk.risk_score` |

---

## Session Risk Tracking

**File:** `policy_engine.py:546–630`

`SessionRiskTracker` maintains a running suspicion score across the lifetime of an agent session.

### Risk Deltas

| Outcome | Delta |
|---|---|
| `Deny` | +0.30 |
| `Confirm` | +0.12 |
| `Guide` | +0.04 |
| `Proceed` | −0.02 |

### Thresholds

| Threshold | Default | Behavior |
|---|---|---|
| `risk_threshold` | 0.45 | Adaptive: +0.15 added to confidence threshold when exceeded |
| `lockout_threshold` | 0.75 | Session locked; all subsequent calls → `Deny` |

### Velocity Anomaly

`check_velocity()` counts calls in the last `velocity_window` seconds (default 60 s). More than `velocity_limit` calls (default 15) in the window sets `velocity_anomaly = True` and applies a `Confirm` risk delta (+0.12). Anomalous call rate is a weak session-level signal, not a hard block.

---

## Key Data Structures

### ProvenanceContext

**File:** `policy_engine.py:293–417`

```python
@dataclass
class ProvenanceContext:
    operator_id: str
    operator_roles: set[str]
    trusted_operator_directive: str
    written_policy: str
    allowed_environments: set[str]          # default: {"staging", "prod"}
    owned_resources: set[str]               # default: empty (deny-all)
    denylisted_destinations: set[str]       # explicit egress blocklist
    sensitive_parameters: set[str]          # args that force Confirm
    untrusted_external_data: list[dict]     # [{source, content}]
    dry_run_ttl_seconds: float              # default: 300.0
    _ledger: AbstractDryRunLedger           # default: InMemoryLedger
```

### Dry-Run Ledger

**File:** `policy_engine.py:239–285`

`AbstractDryRunLedger` defines the interface. `InMemoryLedger` is the default in-process implementation. `record_dry_run(env, resource_id, config)` stores a `DryRunRecord` keyed on `(env, resource_id, sha256(config))`. `verify_dry_run_prerequisite(env, resource_id, config)` checks for a matching record within TTL.

For production: swap `InMemoryLedger` with a `DynamoDBLedger` subclass to persist dry-run records across agent restarts and distributed deployments.

### IntentLockPolicyHandler

**File:** `policy_engine.py:949+`

```python
class IntentLockPolicyHandler:
    client: LocalDeciderClient
    context: ProvenanceContext
    confidence_threshold: float      # default: 0.70
    max_guide_retries: int           # default: 1
    fail_open: bool                  # default: False

    _session_ops: list[dict]         # last N tool outcomes (ring buffer)
    _approved_value_pool: set[str]   # tokenized string values from approved calls
    audit_log: list[dict]            # every call record appended here
    session_risk: SessionRiskTracker
    _retry_counts: dict[str, int]    # Guide retry budget per (stage:tool_name) key
```

---

## Audit Log Schema

Each call to `evaluate_tool_call()` appends one record to `audit_log`:

| Field | Type | Description |
|---|---|---|
| `policy_version` | str | `POLICY_VERSION` constant |
| `checkpoint` | str | Decider model checkpoint name |
| `tool` | str | Tool name |
| `stage_resolved` | str | `"Stage 1 (Deterministic)"` / `"Stage 2 (Decider)"` / `"Session Lock"` |
| `decider_invoked` | bool | Whether the Decider was actually called |
| `cache_hit` | bool | Whether response came from cache |
| `was_cold_start` | bool | First warm inference of the session |
| `injection_signal` | bool | Any Stage 0 hit |
| `injection_hits` | list | Up to 3 matched pattern descriptions |
| `velocity_anomaly` | bool | Velocity threshold exceeded |
| `calls_in_window` | int | Calls in last `velocity_window` seconds |
| `provenance_choice` | str\|None | argmax label |
| `provenance_conf` | float\|None | confidence |
| `egress_choice` | str\|None | argmax label |
| `egress_conf` | float\|None | confidence |
| `privilege_choice` | str\|None | argmax label |
| `privilege_conf` | float\|None | confidence |
| `arg_align_choice` | str\|None | `"yes"` / `"no"` |
| `arg_align_conf` | float\|None | confidence |
| `composite_threat_score` | float | 0–1 fused threat signal |
| `session_risk_score` | float | Accumulated session risk |
| `outcome` | str | `Proceed` / `Confirm` / `Guide` / `Deny` |
| `reason` | str | Human-readable decision reason |
| `explanation` | str | One-sentence policy trigger summary |
| `remediation` | str | Actionable hint for the operator |
| `latency_ms` | float | End-to-end evaluation latency |

### Export Formats

`export_audit(fmt=)` supports three formats:

| fmt | Description | Use case |
|---|---|---|
| `"jsonl"` | Newline-delimited JSON | CloudWatch Logs / S3 / SIEM ingestion |
| `"csv"` | Comma-separated, flattened | Spreadsheet / pandas analysis |
| `"html"` | Self-contained dark-theme report | Security analyst review, stakeholder demo |

The HTML report includes: stat cards (Proceed / Confirm / Guide / Deny counts), a color-coded call timeline table, threat score bars, collapsible raw details, and an inline SVG threat score sparkline (`_build_threat_chart()`).

---

## Configuration Reference

| Parameter | Location | Default | Description |
|---|---|---|---|
| `POLICY_VERSION` | module constant | `"2026.10.10"` | Stamped on every audit record |
| `DEFAULT_CHECKPOINT` | module constant | `StrandsAgents/strands-decider-2B-qwen3.5-v1-2610` | Default model ID |
| `confidence_threshold` | `IntentLockPolicyHandler` | `0.70` | Minimum confidence to treat an answer as definitive |
| `max_guide_retries` | `IntentLockPolicyHandler` | `1` | Guide retry budget before escalating to Deny |
| `fail_open` | `IntentLockPolicyHandler` | `False` | Never set to True in production |
| `dry_run_ttl_seconds` | `ProvenanceContext` | `300.0` | Max age of a valid dry-run record |
| `circuit_breaker_threshold` | `LocalDeciderClient` | `3` | Consecutive failures before circuit opens |
| `circuit_reset_seconds` | `LocalDeciderClient` | `60` | Circuit reset interval |
| `cache_ttl_seconds` | `LocalDeciderClient` | `60` | Response cache TTL |
| `risk_threshold` | `SessionRiskTracker` | `0.45` | Risk score that tightens confidence threshold |
| `lockout_threshold` | `SessionRiskTracker` | `0.75` | Risk score that locks the session |
| `velocity_window` | `SessionRiskTracker` | `60` s | Velocity anomaly measurement window |
| `velocity_limit` | `SessionRiskTracker` | `15` | Max calls per window before anomaly flag |

---

## Quick Start

```python
from intentlock.policy_engine import (
    IntentLockPolicyHandler, LocalDeciderClient, ProvenanceContext
)

ctx = ProvenanceContext(
    operator_id="sre-bot",
    operator_roles={"operator"},
    trusted_operator_directive="Deploy version 3.2 to staging only.",
    written_policy=POLICY_TEXT,
    allowed_environments={"staging"},
    owned_resources={"web-1", "web-2"},
)

handler = IntentLockPolicyHandler(
    client=LocalDeciderClient(endpoint="http://127.0.0.1:8099/v1/systemone"),
    context=ctx,
)

# Strands Agent SDK integration
agent = Agent(model=model, tools=my_tools, interventions=[handler])

# Manual evaluation
outcome, action, record = handler.evaluate_tool_call(
    "apply_cloud_config",
    {"resource_id": "web-1", "environment": "staging", "config": {...}}
)

# Export audit report
html = handler.export_audit(fmt="html")
```

No-server offline demo: `python demo_mock.py && open demo_report.html`

---

## Production Deployment Path

| Component | Dev/Demo | Production |
|---|---|---|
| Decider server | `strands-decider serve --device mps --port 8099` | ECS task or SageMaker endpoint |
| Dry-run ledger | `InMemoryLedger` (in-process) | `DynamoDBLedger(table="intentlock-dryruns")` |
| Audit export | `export_audit(fmt="html")` to local file | `export_audit(fmt="jsonl")` → CloudWatch Logs / S3 |
| Metrics | Per-call `latency_ms` in audit log | CloudWatch custom metrics from JSONL stream |
| Session risk | In-memory, per-handler instance | Serialize `session_risk.risk_score` to DynamoDB for cross-invocation continuity |

---

## File Index

| File | Purpose |
|---|---|
| `intentlock/policy_engine.py` | Core engine (2112 lines) |
| `test_policy_engine.py` | 80 offline unit tests |
| `demo_mock.py` | 5-scenario offline demo, no server needed |
| `agent_demo.py` | Live Bedrock agent + comparison harness |
| `demo_report.html` | Pre-generated HTML audit report |
| `ARTICLE_DRAFT.md` | Builder Center article |
| `README.md` | Hackathon submission overview |
| `ARCHITECTURE.md` | This file |
