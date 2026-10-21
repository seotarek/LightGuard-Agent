# 📋 Executive CISO & Compliance Reporting

Enterprises require proof of security posture for CISOs, compliance boards, and regulatory audits.

LightGuard-Agent provides automated compliance mapping against:
- **OWASP Top 10 for LLMs:** Full coverage for `LLM01` (Prompt Injection), `LLM02` (Sensitive Information Disclosure), and `LLM06` (Excessive Agency).
- **MITRE ATLAS Matrix:** Adversarial Threat Landscape for Artificial Intelligence Systems (`AML.T0054`, `AML.T0051`, `AML.T0025`).

---

## 🚀 Generate Reports

```bash
# Generate single-file standalone HTML executive report
lightguard report --format html --output audit_report.html

# Or export structured JSON for enterprise GRC dashboards
lightguard report --format json
```
