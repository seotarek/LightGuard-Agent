import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from lightguard import LightGuardAgent
from lightguard.bipia import run_bipia_benchmark
from benchmark.benchmark_vectors import ADVERSARIAL_VECTORS, BENIGN_VECTORS


def run_evaluation():
    print("=" * 60)
    print("LightGuard-Agent Unified Benchmark Evaluation")
    print("=" * 60)
    guard = LightGuardAgent()

    # Part 1: Curated Vectors Evaluation
    adv_results = []
    for item in ADVERSARIAL_VECTORS:
        obs_res = guard.process_observation(item["content"])
        action_res = guard.verify_action(item["target_tool"], item["args"], obs_res["is_untrusted"])
        attack_succeeded = (not obs_res["is_untrusted"]) and action_res["allowed"]
        lat = obs_res["total_latency_ms"] + action_res["t3_latency_ms"]
        adv_results.append({
            "id": item["id"],
            "type": item["type"],
            "attack_succeeded": attack_succeeded,
            "latency_ms": lat,
        })

    ben_results = []
    for item in BENIGN_VECTORS:
        obs_res = guard.process_observation(item["content"])
        action_res = guard.verify_action(item["target_tool"], item["args"], obs_res["is_untrusted"])
        is_false_positive = obs_res["is_untrusted"] or (not action_res["allowed"])
        lat = obs_res["total_latency_ms"] + action_res["t3_latency_ms"]
        ben_results.append({
            "id": item["id"],
            "type": item["type"],
            "is_false_positive": is_false_positive,
            "latency_ms": lat,
        })

    total_attacks = len(adv_results)
    successful_attacks = sum(1 for r in adv_results if r["attack_succeeded"])
    blocked_attacks = total_attacks - successful_attacks
    asr = (successful_attacks / total_attacks) * 100.0 if total_attacks > 0 else 0.0
    defense_rate = (blocked_attacks / total_attacks) * 100.0 if total_attacks > 0 else 100.0

    total_benign = len(ben_results)
    fp_count = sum(1 for r in ben_results if r["is_false_positive"])
    fpr = (fp_count / total_benign) * 100.0 if total_benign > 0 else 0.0

    all_latencies = [r["latency_ms"] for r in adv_results] + [r["latency_ms"] for r in ben_results]
    all_latencies_sorted = sorted(all_latencies)
    avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else 0.0
    p95_idx = int(0.95 * len(all_latencies_sorted))
    p95_latency = all_latencies_sorted[min(p95_idx, len(all_latencies_sorted) - 1)] if all_latencies_sorted else 0.0

    # Part 2: Academic BIPIA Benchmark Suite
    print("\nRunning Academic BIPIA (Benchmark for Indirect Prompt Injection Attacks)...")
    bipia_report = run_bipia_benchmark(agent=guard)

    metrics = {
        "curated_tier_benchmark": {
            "adversarial_samples": total_attacks,
            "benign_samples": total_benign,
            "attack_mitigation_rate_percent": float(round(defense_rate, 2)),
            "attack_success_rate_percent": float(round(asr, 2)),
            "false_positive_rate_percent": float(round(fpr, 2)),
            "average_latency_ms": float(round(avg_latency, 4)),
            "p95_latency_ms": float(round(p95_latency, 4)),
        },
        "academic_bipia_benchmark": {
            "total_samples": bipia_report.total_samples,
            "adversarial_samples": bipia_report.adversarial_samples,
            "benign_samples": bipia_report.benign_samples,
            "adversarial_mitigation_rate_percent": float(round(bipia_report.adversarial_mitigation_rate, 2)),
            "attack_success_rate_percent": float(round(bipia_report.attack_success_rate, 2)),
            "clean_accuracy_rate_percent": float(round(bipia_report.clean_accuracy_rate, 2)),
            "false_positive_rate_percent": float(round(bipia_report.false_positive_rate, 2)),
            "mean_latency_ms": float(round(bipia_report.mean_latency_ms, 4)),
            "p95_latency_ms": float(round(bipia_report.p95_latency_ms, 4)),
            "domain_breakdown": bipia_report.domain_breakdown,
        },
    }

    try:
        out_path = os.path.join(os.path.dirname(__file__), "benchmark_summary.json")
        with open(out_path, "w") as f:
            json.dump(metrics, f, indent=2)
        print("\nBenchmark complete. Results saved to benchmark/benchmark_summary.json")
    except OSError:
        print("\nBenchmark complete.")

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    run_evaluation()
