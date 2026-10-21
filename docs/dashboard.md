# Local Web Control Center & Dashboard

LightGuard-Agent v0.6.0 includes a zero-dependency, local web control center powered directly by Python's standard library `http.server`. It provides an interactive browser-based interface to test observations, simulate tool execution, view Prometheus telemetry, and export executive compliance audits.

---

## 🚀 Quick Launch

Launch the dashboard from your terminal:

```bash
lightguard dashboard
```

Output:
```
🛡️  LightGuard-Agent Local Control Center live at http://127.0.0.1:8443
Press Ctrl+C to stop.
```

To specify custom host or port:

```bash
lightguard dashboard --host 0.0.0.0 --port 9090
```

---

## 🖥️ Web Control Features

1. **Interactive Observation Scanner**:
   - Paste raw untrusted inputs or prompt injections.
   - Select proposed agent actions (e.g. `delete_file`, `send_email`, `search_docs`).
   - Instantly inspect risk scores, tier flaggers, and Action Firewall decisions.

2. **Executive Compliance Reports**:
   - Access `/report` directly from your browser to view and download full HTML compliance audits mapped to OWASP Top 10 for LLMs and MITRE ATLAS.

3. **Prometheus Metrics Endpoint**:
   - Integrated `/metrics` endpoint ready for Prometheus scraping without external exporter daemons.

---

## 🐍 Programmatic Usage

You can also embed and launch the dashboard directly from your Python scripts:

```python
from lightguard import run_dashboard

# Launch in a background thread or process
run_dashboard(host="127.0.0.1", port=8443)
```
