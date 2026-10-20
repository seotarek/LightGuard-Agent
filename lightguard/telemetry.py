import dataclasses
import threading
import time


@dataclasses.dataclass
class TelemetrySnapshot:
    total_observations_scanned: int
    injections_blocked: int
    obfuscations_detected: int
    canary_violations: int
    pii_redactions: int
    high_stakes_actions_blocked: int
    mean_latency_ms: float
    p95_latency_ms: float
    timestamp: float


class SecurityTelemetryCollector:
    """
    Lightweight, thread-safe security telemetry and Prometheus metrics collector.
    Exposes metrics for Prometheus, Datadog, Grafana, and OpenTelemetry monitoring.
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self.total_observations = 0
        self.injections_blocked = 0
        self.obfuscations_detected = 0
        self.canary_violations = 0
        self.pii_redactions = 0
        self.high_stakes_blocked = 0
        self.latencies: list[float] = []

    @classmethod
    def get_instance(cls) -> "SecurityTelemetryCollector":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def record_observation(
        self,
        is_blocked: bool,
        was_obfuscated: bool,
        canary_violated: bool,
        latency_ms: float,
    ) -> None:
        with self._lock:
            self.total_observations += 1
            if is_blocked:
                self.injections_blocked += 1
            if was_obfuscated:
                self.obfuscations_detected += 1
            if canary_violated:
                self.canary_violations += 1
            # Keep sliding window of latest 5000 latency measurements
            self.latencies.append(latency_ms)
            if len(self.latencies) > 5000:
                self.latencies.pop(0)

    def record_action_block(self) -> None:
        with self._lock:
            self.high_stakes_blocked += 1

    def record_pii_redaction(self, count: int = 1) -> None:
        with self._lock:
            self.pii_redactions += count

    def get_snapshot(self) -> TelemetrySnapshot:
        with self._lock:
            total_obs = self.total_observations
            inj_blocked = self.injections_blocked
            obf_detected = self.obfuscations_detected
            can_viol = self.canary_violations
            pii_red = self.pii_redactions
            hs_blocked = self.high_stakes_blocked
            lats = list(self.latencies)

        mean_lat = sum(lats) / len(lats) if lats else 0.0
        sorted_lats = sorted(lats)
        p95_idx = int(len(sorted_lats) * 0.95)
        p95_lat = sorted_lats[p95_idx] if sorted_lats else 0.0

        return TelemetrySnapshot(
            total_observations_scanned=total_obs,
            injections_blocked=inj_blocked,
            obfuscations_detected=obf_detected,
            canary_violations=can_viol,
            pii_redactions=pii_red,
            high_stakes_actions_blocked=hs_blocked,
            mean_latency_ms=round(mean_lat, 4),
            p95_latency_ms=round(p95_lat, 4),
            timestamp=time.time(),
        )

    def export_prometheus(self) -> str:
        """Exports metrics in standard Prometheus text exposition format."""
        s = self.get_snapshot()
        lines = [
            "# HELP lightguard_observations_scanned_total Total untrusted observations inspected",
            "# TYPE lightguard_observations_scanned_total counter",
            f"lightguard_observations_scanned_total {s.total_observations_scanned}",
            "# HELP lightguard_injections_blocked_total Total prompt injections blocked",
            "# TYPE lightguard_injections_blocked_total counter",
            f"lightguard_injections_blocked_total {s.injections_blocked}",
            "# HELP lightguard_obfuscations_detected_total Total obfuscation attacks detected",
            "# TYPE lightguard_obfuscations_detected_total counter",
            f"lightguard_obfuscations_detected_total {s.obfuscations_detected}",
            "# HELP lightguard_canary_violations_total Total canary exfiltration attempts blocked",
            "# TYPE lightguard_canary_violations_total counter",
            f"lightguard_canary_violations_total {s.canary_violations}",
            "# HELP lightguard_pii_redactions_total Total PII and secret tokens redacted",
            "# TYPE lightguard_pii_redactions_total counter",
            f"lightguard_pii_redactions_total {s.pii_redactions}",
            "# HELP lightguard_latency_mean_ms Mean evaluation latency in milliseconds",
            "# TYPE lightguard_latency_mean_ms gauge",
            f"lightguard_latency_mean_ms {s.mean_latency_ms:.4f}",
            "# HELP lightguard_latency_p95_ms 95th percentile latency in milliseconds",
            "# TYPE lightguard_latency_p95_ms gauge",
            f"lightguard_latency_p95_ms {s.p95_latency_ms:.4f}",
        ]
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self.total_observations = 0
            self.injections_blocked = 0
            self.obfuscations_detected = 0
            self.canary_violations = 0
            self.pii_redactions = 0
            self.high_stakes_blocked = 0
            self.latencies.clear()
