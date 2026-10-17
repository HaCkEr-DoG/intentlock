# IntentLock

**IntentLock** is a provenance-aware temporal policy engine for agentic cloud InfraOps.

It uses [Strands Decider 2B](https://strandsagents.com/blog/introducing-strands-decider-2b/) to answer two orthogonal policy questions before any infrastructure tool call executes, paired with Amazon Bedrock for the generative agent layer.

**Hackathon tags:** `#strands-decider-2b` `#policy`

---

## Decision pattern: Policy

Before every tool call the agent proposes, IntentLock asks Strands Decider 2B two batched `choice` questions in a single `/v1/systemone` request:

| Question ID | Options |
|---|---|
| `provenance_verdict` | `trusted_operator` · `ungrounded_guess` · `untrusted_injection` |
| `data_egress_policy` | `internal_scoped` · `ambiguous_scope` · `unauthorized_egress` |

The two answers feed a most-restrictive-wins mapping: `Proceed`, `Guide`, `Deny`, or `Confirm`. Deterministic Stage 1 checks (RBAC, ownership, environment allowlist, egress denylist, dry-run prerequisite) fast-fail obvious violations before the model is ever invoked.

### Reusable pattern

`intentlock/policy_engine.py` contains the standalone pattern:
- **`INTENTLOCK_QUESTIONS`** — the complete typed question and option set.
- **`IntentLockPolicyHandler`** — a Strands `InterventionHandler` with `before_tool_call` and `before_invocation` that another builder can wire into any Strands agent with `Agent(interventions=[handler])`.
- **`ProvenanceContext`** — holds the immutable operator directive, ownership registry, environment allowlist, and digest-bound dry-run ledger separately from the conversation.

---

## Setup

```bash
# 1. Create a Python 3.12 virtual environment
uv venv --python 3.12 .venv
source .venv/bin/activate

# 2. Install dependencies (requires PyPI access)
pip install -r requirements.txt

# 3. Run offline unit tests (no server needed)
python -m unittest -v test_policy_engine.py
```

---

## Running the policy harness

### Terminal 1 — start the local Decider server

**Important:** On first run, `strands-decider serve` downloads the `Qwen/Qwen3.5-2B-Base` base model (~4.5 GB). Set a HuggingFace token first to avoid rate-limiting:

```bash
export HF_TOKEN=hf_YOUR_TOKEN_HERE   # get at huggingface.co → Settings → Access Tokens
```

Then start the server (MPS for Apple Silicon Metal, or omit `--device` for auto-detect):

```bash
strands-decider serve \
  StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 \
  --device mps \
  --port 8099
```

Wait for the server to print `Application startup complete.` before running the harness.

### Terminal 2 — run the seven-scenario harness

```bash
python run_eval_harness.py \
  --base-url http://127.0.0.1:8099 \
  --repeat 5 \
  --output results/intentlock_eval_results.json
```

The harness checks `/health` and requires an MLX backend report before proceeding by default. Pass `--allow-non-mlx` when running on MPS. Results are written as JSON with per-scenario decisions, confidence scores, latency statistics, and implementation integrity probes.

---

## AWS credentials for Bedrock

The generative Strands Agent layer requires:

```bash
aws configure          # or set AWS_REGION + credentials in the environment
```

Ensure `us.anthropic.claude-haiku-4-5-20251001-v1:0` (or your chosen model) is enabled in the Bedrock console under **Model access** for your region.

---

## Project structure

```
intentlock/
  __init__.py
  policy_engine.py         ← policy engine + reusable decision pattern
test_policy_engine.py      ← 12 offline unit tests
run_eval_harness.py        ← 7-scenario + integrity probe harness
requirements.txt
pyproject.toml
README.md
INTENTLOCK_POLICY_PATCH_README.md   ← patch notes and limitations
intentlock_mock_eval_results.json   ← mock interface run (not real MLX metrics)
```

---

## Known limitations

- The dry-run ledger is an in-process object, not a tamper-proof audit store. Only trusted tool code should call `record_dry_run(..., succeeded=True)` after a real structured success.
- Decider confidence is not a security guarantee. Thresholds need empirical validation on your hardware and real scenarios.
- The Bedrock-backed end-to-end demo has not been executed; compile and unit tests do not prove installed-package compatibility or intervention lifecycle behaviour.
- Latency numbers in the article are from the published Strands Decider 2B model card benchmarks. Run `run_eval_harness.py` against a live server for your own hardware numbers.

---

## License

MIT
