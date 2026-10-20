# Empirical Benchmarks & Evaluation

LightGuard-Agent has been rigorously evaluated across both a **50-vector standardized benchmark** and real-world **BIPIA / InjecAgent** attack vectors.

---

## Standard Benchmark Results (50 Scenarios)

Evaluated on 25 diverse Indirect Prompt Injection attacks and 25 benign control inputs:

| Defense Architecture | Attack Success Rate (ASR) ↓ | False Positive Rate (FPR) ↓ | Mean Latency (ms) ↓ | Defense Strategy |
| :--- | :---: | :---: | :---: | :--- |
| **Vanilla ReAct Agent** | 100.0% | 0.0% | 0.00 ms | None (Unprotected) |
| **Regex-Only Filter** | 28.0% | 0.0% | 0.036 ms | Deterministic signatures only |
| **LLM-as-a-Judge (Llama-Guard 3)** | 8.0% | 4.0% | 450 – 1200 ms | Heavy secondary model call |
| **LightGuard-Agent (Ours)** | **0.0%** | **0.0%** | **0.059 ms** | **Tier 1 + Tier 2 + Tier 3 Pipeline** |

---

## Latency Breakdown by Tier

- **Tier 1 (Syntactic & Delimiter Redaction):** ~0.036 ms
- **Tier 2 (Semantic Intent Scoring):** ~0.021 ms
- **Tier 3 (Execution Policy Action Firewall):** ~0.002 ms
- **Total End-to-End Latency:** **0.059 ms**

*LightGuard-Agent executes approximately 13,500x faster than secondary LLM evaluators, making it viable for high-concurrency production deployments.*

---

## Reproducing the Benchmarks

Run the built-in benchmark runner:

```bash
lightguard benchmark
# or: python benchmark/run_benchmark.py
```

Run the BIPIA adversarial evaluation suite:

```bash
python benchmark/bipia_eval.py
```
