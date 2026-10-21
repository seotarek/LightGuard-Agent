from lightguard.reporting import ComplianceReportGenerator


def test_compliance_report_generator_data():
    gen = ComplianceReportGenerator()
    data = gen.generate_audit_data()

    assert data["overall_status"] == "COMPLIANT"
    assert data["defense_rate"] == "100.0%"
    assert data["false_positive_rate"] == "0.0%"
    assert len(data["owasp_mapping"]) == 3
    assert len(data["mitre_atlas_mapping"]) == 3


def test_compliance_report_generator_html():
    gen = ComplianceReportGenerator()
    html = gen.generate_html_report()

    assert "<!DOCTYPE html>" in html
    assert "OWASP Top 10 for LLMs" in html
    assert "MITRE ATLAS" in html
    assert "LightGuard-Agent Executive Security Audit" in html
