# Automated Adversarial Red-Teaming

LightGuard-Agent includes a built-in automated penetration testing engine to evaluate agents, models, and endpoints against known adversarial vectors.

---

## Running from the CLI

Run the full penetration suite with a single command:

```bash
lightguard audit
# or using the alias
lightguard redteam
```

### Sample Output:

```
========================================================================
         LIGHTGUARD-AGENT ADVERSARIAL RED-TEAM AUDIT REPORT
========================================================================
Total Vectors Evaluated:        26
Vectors Successfully Defended:  26 / 26
Adversarial Mitigation Rate:    100.0%
Benign Retention (No False Pos): 100.0%
False Positive Rate (FPR):      0.0%
Mean Defense Latency:           0.1628 ms
P95 Defense Latency:            0.3776 ms
------------------------------------------------------------------------
ATTACK CATEGORY                | TOTAL  | DEFENDED | PASS %   | LATENCY
------------------------------------------------------------------------
Direct Prompt Injection        | 5      | 5        |  100.0% | 0.153 ms
Indirect Prompt Injection      | 4      | 4        |  100.0% | 0.112 ms
Delimiter Injection            | 3      | 3        |  100.0% | 0.337 ms
Obfuscation & Evasion          | 5      | 5        |  100.0% | 0.170 ms
Action Firewall                | 3      | 3        |  100.0% | 0.122 ms
Benign Controls                | 5      | 5        |  100.0% | 0.127 ms
Multi-Turn Escalation          | 1      | 1        |  100.0% | 0.150 ms
========================================================================
STATUS: ALL ADVERSARIAL ATTACKS NEUTRALIZED (ZERO FALSE POSITIVES)
========================================================================
```

---

## Programmatic Auditing in Python

You can integrate the audit engine directly into continuous integration (CI) tests:

```python
from lightguard.redteam import run_redteam_audit

def test_security_posture():
    report = run_redteam_audit()
    assert report.adversarial_mitigation_rate == 100.0
    assert report.false_positive_rate == 0.0
    assert report.mean_latency_ms < 1.0
```
