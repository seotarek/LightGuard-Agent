from lightguard.redteam import format_audit_report, run_redteam_audit


def test_redteam_audit_runs_and_passes():
    report = run_redteam_audit()
    assert report.total_vectors >= 20
    assert report.adversarial_mitigation_rate == 100.0
    assert report.false_positive_rate == 0.0
    assert report.mean_latency_ms < 1.0  # Must be strictly sub-millisecond

    formatted = format_audit_report(report)
    assert "LIGHTGUARD-AGENT ADVERSARIAL RED-TEAM AUDIT REPORT" in formatted
    assert "ALL ADVERSARIAL ATTACKS NEUTRALIZED" in formatted
