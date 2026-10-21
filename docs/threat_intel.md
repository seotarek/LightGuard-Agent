# Offline Threat Intelligence & Custom Signature Registry

LightGuard-Agent v0.6.0 provides enterprise teams with an offline threat intelligence registry (`ThreatIntelRegistry`). This allows security operations centers (SOC) to update jailbreak signatures, exfiltration sink URLs, and restricted agent tools without rebuilding or re-installing the core Python package.

---

## 🔒 Cryptographic Integrity

Threat intelligence feeds are serialized as JSON and validated using SHA-256 cryptographic checksums. If a feed is corrupted or tampered with in transit, import is aborted immediately.

---

## 🛠️ Usage Example

```python
from lightguard import ThreatIntelRegistry

registry = ThreatIntelRegistry()

# 1. Inspect baseline signatures
print(f"Total verified signatures: {registry.total_signatures}")

# 2. Register custom enterprise signature
registry.register_signature(
    signature_id="CORP-SEC-01",
    pattern=r"override\s+company\s+compliance",
    category="COMPLIANCE_BYPASS",
    severity="CRITICAL",
    description="Blocks internal audit bypass patterns",
)

# 3. Export feed with cryptographic SHA-256
feed_json = registry.export_feed_json()

# 4. Import feed safely
new_registry = ThreatIntelRegistry()
new_registry.import_feed_json(feed_json)
```
