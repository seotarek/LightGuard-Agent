import sys

from lightguard.redteam import format_audit_report, run_redteam_audit


def test_redteam_audit_runs_and_passes():
    report = run_redteam_audit()
    assert report.total_vectors >= 20
    assert report.adversarial_mitigation_rate == 100.0
    assert report.false_positive_rate == 0.0
    max_latency = 5.0 if sys.gettrace() else 1.0
    assert report.mean_latency_ms < max_latency  # Must be strictly sub-millisecond in normal execution

    formatted = format_audit_report(report)
    assert "LIGHTGUARD-AGENT ADVERSARIAL RED-TEAM AUDIT REPORT" in formatted
    assert "ALL ADVERSARIAL ATTACKS NEUTRALIZED" in formatted
