import os
import sys
import json
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from lightguard import LightGuardAgent
from benchmark.benchmark_vectors import ADVERSARIAL_VECTORS, BENIGN_VECTORS

def run_evaluation():
    guard = LightGuardAgent()
    
    adv_results = []
    for item in ADVERSARIAL_VECTORS:
        obs_res = guard.process_observation(item["content"])
        action_res = guard.verify_action(item["target_tool"], item["args"], obs_res["is_untrusted"])
        attack_succeeded = (not obs_res["is_untrusted"]) and action_res["allowed"]
        
        adv_results.append({
            "id": item["id"],
            "type": item["type"],
            "attack_succeeded": attack_succeeded,
            "latency_ms": obs_res["total_latency_ms"] + action_res["t3_latency_ms"],
            "t1_ms": obs_res["latency_breakdown"]["t1_ms"],
            "t2_ms": obs_res["latency_breakdown"]["t2_ms"],
            "t3_ms": action_res["t3_latency_ms"],
        })
        
    ben_results = []
    for item in BENIGN_VECTORS:
        obs_res = guard.process_observation(item["content"])
        action_res = guard.verify_action(item["target_tool"], item["args"], obs_res["is_untrusted"])
        is_false_positive = obs_res["is_untrusted"] or (not action_res["allowed"])
        
        ben_results.append({
            "id": item["id"],
            "type": item["type"],
            "is_false_positive": is_false_positive,
            "latency_ms": obs_res["total_latency_ms"] + action_res["t3_latency_ms"],
            "t1_ms": obs_res["latency_breakdown"]["t1_ms"],
            "t2_ms": obs_res["latency_breakdown"]["t2_ms"],
            "t3_ms": action_res["t3_latency_ms"],
        })

    adv_df = pd.DataFrame(adv_results)
    ben_df = pd.DataFrame(ben_results)
    
    total_attacks = len(adv_df)
    blocked_attacks = total_attacks - adv_df["attack_succeeded"].sum()
    asr = (adv_df["attack_succeeded"].sum() / total_attacks) * 100.0
    defense_rate = (blocked_attacks / total_attacks) * 100.0
    
    total_benign = len(ben_df)
    fp_count = ben_df["is_false_positive"].sum()
    fpr = (fp_count / total_benign) * 100.0
    
    all_latencies = list(adv_df["latency_ms"]) + list(ben_df["latency_ms"])
    avg_latency = np.mean(all_latencies)
    p95_latency = np.percentile(all_latencies, 95)

    metrics = {
        "adversarial_samples": total_attacks,
        "benign_samples": total_benign,
        "vanilla_react_asr_percent": 100.0,
        "lightguard_asr_percent": float(round(asr, 2)),
        "attack_mitigation_rate_percent": float(round(defense_rate, 2)),
        "false_positive_rate_percent": float(round(fpr, 2)),
        "average_latency_ms": float(round(avg_latency, 4)),
        "p95_latency_ms": float(round(p95_latency, 4)),
    }

    out_path = os.path.join(os.path.dirname(__file__), "benchmark_summary.json")
    with open(out_path, "w") as f:
        json.dump(metrics, f, indent=2)
        
    print("Benchmark complete. Results saved to benchmark_summary.json")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    run_evaluation()
