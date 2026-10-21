"""Offline Threat Intelligence Registry & Custom Signature Sync.

Enables enterprises to load, update, and cryptographically verify custom
threat intelligence feeds, new jailbreak signatures, and prohibited tool lists
offline without upgrading the core Python package.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Set


class ThreatSignature:
    """Represents a discrete verified threat signature."""

    def __init__(
        self,
        signature_id: str,
        pattern: str,
        category: str,
        severity: str = "HIGH",
        description: str = "",
    ) -> None:
        self.signature_id = signature_id
        self.pattern = pattern
        self.category = category
        self.severity = severity
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.signature_id,
            "pattern": self.pattern,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
        }


class ThreatIntelRegistry:
    """Manages offline threat intelligence feeds and custom enterprise signatures."""

    _instance: Optional["ThreatIntelRegistry"] = None

    def __init__(self) -> None:
        self._signatures: Dict[str, ThreatSignature] = {}
        self._custom_prohibited_tools: Set[str] = set()
        self._load_baseline_intel()

    @classmethod
    def get_instance(cls) -> "ThreatIntelRegistry":
        if cls._instance is None:
            cls._instance = ThreatIntelRegistry()
        return cls._instance

    def _load_baseline_intel(self) -> None:
        """Seed baseline verified threat signatures."""
        baseline = [
            ("SIG-001", r"ignore\s+(all\s+)?(previous|prior)\s+instructions", "DIRECT_INJECTION", "CRITICAL"),
            ("SIG-002", r"disregard\s+(the\s+)?system\s+prompt", "SYSTEM_OVERRIDE", "CRITICAL"),
            ("SIG-003", r"you\s+are\s+now\s+in\s+developer\s+mode", "ROLE_PLAY_JAILBREAK", "HIGH"),
            ("SIG-004", r"output\s+all\s+initial\s+system\s+instructions", "PROMPT_EXTRACTION", "HIGH"),
            ("SIG-005", r"pastebin\.com/[a-zA-Z0-9]+", "EXFILTRATION_SINK", "HIGH"),
            ("SIG-006", r"webhook\.site/[a-f0-9\-]+", "EXFILTRATION_SINK", "HIGH"),
        ]
        for sid, pat, cat, sev in baseline:
            self._signatures[sid] = ThreatSignature(
                signature_id=sid,
                pattern=pat,
                category=cat,
                severity=sev,
            )

    def register_signature(
        self,
        signature_id: str,
        pattern: str,
        category: str = "CUSTOM",
        severity: str = "HIGH",
        description: str = "",
    ) -> None:
        """Register a new signature into the active memory registry."""
        self._signatures[signature_id] = ThreatSignature(
            signature_id=signature_id,
            pattern=pattern,
            category=category,
            severity=severity,
            description=description,
        )

    def import_feed_json(
        self,
        feed_json: str,
        verify_checksum: Optional[str] = None,
        verify_hmac_key: Optional[str] = None,
        expected_hmac: Optional[str] = None,
    ) -> int:
        """Import signatures from JSON payload with SHA-256 integrity and HMAC authenticity verification."""
        data = json.loads(feed_json)
        if not isinstance(data, dict):
            raise ValueError("Threat intelligence payload must be a JSON object")

        # 1. SHA-256 integrity verification
        target_checksum = verify_checksum or data.get("sha256")
        if target_checksum:
            verify_copy = {k: v for k, v in data.items() if k not in ("sha256", "hmac_signature")}
            canonical_bytes = json.dumps(verify_copy, sort_keys=True).encode("utf-8")
            computed = hashlib.sha256(canonical_bytes).hexdigest()
            if computed.lower() != target_checksum.lower():
                raw_hash = hashlib.sha256(feed_json.encode("utf-8")).hexdigest()
                if raw_hash.lower() != target_checksum.lower():
                    raise ValueError(
                        f"Threat intelligence checksum mismatch! Expected {target_checksum}, got {computed}"
                    )

        # 2. HMAC authenticity verification (proves trusted publisher identity)
        target_hmac = expected_hmac or data.get("hmac_signature")
        if verify_hmac_key and target_hmac:
            import hmac
            verify_copy = {k: v for k, v in data.items() if k not in ("sha256", "hmac_signature")}
            canonical_bytes = json.dumps(verify_copy, sort_keys=True).encode("utf-8")
            computed_hmac = hmac.new(
                verify_hmac_key.encode("utf-8"),
                canonical_bytes,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(computed_hmac.lower(), target_hmac.lower()):
                raise ValueError(
                    "Threat intelligence HMAC signature verification failed! Publisher authenticity unverified."
                )

        signatures = data.get("signatures", [])
        added_count = 0
        for s in signatures:
            sid = s.get("id")
            pat = s.get("pattern")
            if sid and pat:
                self.register_signature(
                    signature_id=sid,
                    pattern=pat,
                    category=s.get("category", "CUSTOM"),
                    severity=s.get("severity", "HIGH"),
                    description=s.get("description", ""),
                )
                added_count += 1

        tools = data.get("prohibited_tools", [])
        for t in tools:
            self._custom_prohibited_tools.add(t)

        return added_count

    def export_feed_json(self, sign_hmac_key: Optional[str] = None) -> str:
        """Export current threat intel database to verifiable JSON with canonical hash and optional HMAC."""
        data = {
            "version": "1.0",
            "total_signatures": len(self._signatures),
            "prohibited_tools": sorted(self._custom_prohibited_tools),
            "signatures": [s.to_dict() for s in self._signatures.values()],
        }
        canonical_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        data["sha256"] = hashlib.sha256(canonical_bytes).hexdigest()
        if sign_hmac_key:
            import hmac
            data["hmac_signature"] = hmac.new(
                sign_hmac_key.encode("utf-8"),
                canonical_bytes,
                hashlib.sha256,
            ).hexdigest()
        return json.dumps(data, indent=2)

    def get_all_patterns(self) -> List[str]:
        return [s.pattern for s in self._signatures.values()]

    @property
    def total_signatures(self) -> int:
        return len(self._signatures)
