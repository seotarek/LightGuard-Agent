from lightguard.bipia import BIPIABenchmarkReport, run_bipia_benchmark
from lightguard.core import LightGuardAgent


def test_bipia_benchmark_execution():
    agent = LightGuardAgent()
    report = run_bipia_benchmark(guard=agent)

    assert isinstance(report, BIPIABenchmarkReport)
    assert report.total_samples == 12
    assert report.adversarial_samples == 8
    assert report.benign_samples == 4

    # Academic metrics
    assert report.adversarial_mitigation_rate == 100.0
    assert report.attack_success_rate == 0.0
    assert report.clean_accuracy_rate == 100.0
    assert report.false_positive_rate == 0.0
    assert report.mean_latency_ms < 5.0

    # Domain breakdown verification
    assert "email_qa" in report.domain_breakdown
    assert "web_qa" in report.domain_breakdown
    assert "table_qa" in report.domain_breakdown
    assert "code_qa" in report.domain_breakdown

    assert report.domain_breakdown["email_qa"]["adversarial_mitigation_rate"] == 100.0
    assert report.domain_breakdown["web_qa"]["adversarial_mitigation_rate"] == 100.0

    # Serialization test
    d = report.to_dict()
    assert d["adversarial_mitigation_rate"] == 100.0
    assert len(d["task_results"]) == 12
