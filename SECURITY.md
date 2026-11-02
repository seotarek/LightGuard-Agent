# Security Policy

## Threat Model & Supported Versions

LightGuard-Agent is an enterprise runtime firewall engineered to defend tool-calling AI agents, MCP servers, and RAG pipelines against:
- **Indirect Prompt Injection (IPI)**
- **Steganographic & Unicode Homoglyph Evasion**
- **Delimiter & System Prompt Escapes**
- **Canary & Credential Exfiltration**
- **Multi-Turn Crescendo Jailbreaks**
- **Unauthorized Tool Escalation**

| Version | Supported | Status |
| :--- | :--- | :--- |
| `0.7.x` | Yes | Current Stable Release |
| `0.3.x` | Yes | Research Benchmark Baseline |
| `< 0.3.0` | No | Deprecated |

## Reporting a Security Vulnerability

We treat all vulnerability reports with highest urgency. If you discover an evasion technique, false negative bypass, or code execution defect:
1. **Direct Communication**: Send an email to `seotarek@gmail.com` with the subject `[SECURITY] LightGuard Vulnerability Report`.
2. **Payload & PoC**:
   - Provide the exact adversarial payload or reproducible script.
   - Specify the active configuration (thresholds, enabled tiers).
   - Expected verdict vs. observed verdict.
3. **Disclosure Timeline**:
   - We will respond within **48 hours** with an initial triage.
   - A fix will be developed and verified against our automated benchmark suite before a public patch release is issued.
   - We coordinate public CVE/GHSA disclosures responsibly.
