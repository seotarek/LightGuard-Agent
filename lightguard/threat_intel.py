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

    def import_feed_json(self, feed_json: str, verify_checksum: Optional[str] = None) -> int:
        """Import signatures from JSON payload with optional SHA-256 verification."""
        if verify_checksum:
            computed = hashlib.sha256(feed_json.encode("utf-8")).hexdigest()
            if computed.lower() != verify_checksum.lower():
                raise ValueError(
                    f"Threat intelligence checksum mismatch! Expected {verify_checksum}, got {computed}"
                )

        data = json.loads(feed_json)
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

    def export_feed_json(self) -> str:
        """Export current threat intel database to verifiable JSON."""
        data = {
            "version": "1.0",
            "total_signatures": len(self._signatures),
            "prohibited_tools": sorted(self._custom_prohibited_tools),
            "signatures": [s.to_dict() for s in self._signatures.values()],
        }
        raw_json = json.dumps(data, indent=2)
        checksum = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        data["sha256"] = checksum
        return json.dumps(data, indent=2)

    def get_all_patterns(self) -> List[str]:
        return [s.pattern for s in self._signatures.values()]

    @property
    def total_signatures(self) -> int:
        return len(self._signatures)
