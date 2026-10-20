# 🔒 Data Loss Prevention (DLP) & PII Redaction

LightGuard-Agent v0.4.0 includes a zero-dependency, sub-millisecond **Data Loss Prevention (DLP)** and **Personally Identifiable Information (PII)** anonymizer.

When AI agents query external tools, databases, or user inputs, sensitive secrets and private data can accidentally be forwarded to external LLMs or third-party APIs. `PrivacyGuard` scans, redacts, and replaces sensitive tokens with reversible placeholders in under **0.15ms**.

---

## 🛡️ Supported Entity Types

| Category | Entities Detected | Validation Method |
| :--- | :--- | :--- |
| **Financial** | Visa, MasterCard, Amex, Discover | **Luhn Checksum Algorithm** (zero false positives) |
| **API Keys & Secrets** | OpenAI (`sk-...`), Anthropic (`sk-ant-...`), AWS Access Keys (`AKIA...`), GitHub Tokens (`ghp_...`, `gho_...`) | Pattern matching + prefix verification |
| **Government IDs** | US Social Security Numbers (SSN) | Strict 9-digit hyphenated format |
| **Contact Info** | Email Addresses, International Phone Numbers | RFC 5322 regex subset + E.164 patterns |
| **Network** | IPv4 Addresses | Strict octet range `(0-255)` verification |

---

## 🚀 Quick Example

```python
from lightguard import PrivacyGuard

guard = PrivacyGuard()

text = "User email is john.doe@example.com, card is 4532015112830366, key is sk-1234567890abcdef1234567890abcdef."

# Redact sensitive tokens
result = guard.redact(text)

print(result["redacted_text"])
# Output:
# User email is [LG_DLP_EMAIL_001], card is [LG_DLP_CREDIT_CARD_001], key is [LG_DLP_OPENAI_KEY_001].

print(f"Entities Found: {result['entities_found']}")
print(f"Latency: {result['latency_ms']:.4f} ms")
```

---

## 🔄 Reversible Anonymization (`restore`)

In multi-turn agent workflows, you often need to send sanitized text to the LLM, but restore original sensitive IDs before executing a local database query or action:

```python
# Restore redacted text to original form
original_restored = guard.restore(result["redacted_text"], result["entity_map"])

assert original_restored == text
```

---

## ⚡ Integration with LightGuardAgent

`LightGuardAgent` automatically applies DLP redaction when configured with a policy:

```python
from lightguard import LightGuardAgent, SecurityPolicyConfig

agent = LightGuardAgent(policy=SecurityPolicyConfig(enable_dlp=True))

sanitized = agent.process_observation("Sensitive report with email boss@corp.com")
print(sanitized["clean_text"])
```

---

## 💻 CLI Usage

Redact text directly from your terminal:

```bash
lightguard redact "Contact me at alice@domain.org or sk-test1234567890abcdef1234567890"
```
