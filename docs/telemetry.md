# 📈 Prometheus Telemetry & Observability

Enterprise security teams require real-time visibility into adversarial attack frequency, latency percentiles, and threat signatures.

LightGuard-Agent v0.4.0 embeds an in-memory, thread-safe `SecurityTelemetryCollector` that exposes standard **Prometheus** metrics without requiring heavy third-party client dependencies.

---

## 📊 Available Metrics

| Metric Name | Type | Description |
| :--- | :---: | :--- |
| `lightguard_observations_scanned_total` | Counter | Total untrusted observations inspected |
| `lightguard_injections_blocked_total` | Counter | Total prompt injections successfully neutralized |
| `lightguard_obfuscations_detected_total` | Counter | Total steganographic/homoglyph evasion attempts |
| `lightguard_canary_violations_total` | Counter | Total canary exfiltration attempts caught |
| `lightguard_pii_redactions_total` | Counter | Total PII, secrets, and financial tokens redacted |
| `lightguard_latency_mean_ms` | Gauge | Rolling mean inspection latency in milliseconds |
| `lightguard_latency_p95_ms` | Gauge | 95th percentile inspection latency in milliseconds |

---

## 🚀 Quick Example

```python
from lightguard import LightGuardAgent

agent = LightGuardAgent()

# Process observations as normal
agent.process_observation("Observation data...")

# Export Prometheus text format for /metrics endpoint
prom_metrics = agent.telemetry.export_prometheus()
print(prom_metrics)

# Or export JSON snapshot
stats = agent.telemetry.get_snapshot()
print(f"Total Scans: {stats['observations_scanned']}")
print(f"P95 Latency: {stats['latency_p95_ms']:.4f} ms")
```

---

## 💻 CLI Usage

Inspect live telemetry metrics directly from the CLI:

```bash
lightguard metrics
```
