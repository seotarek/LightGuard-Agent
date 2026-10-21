import json

import pytest

from lightguard.threat_intel import ThreatIntelRegistry


def test_threat_intel_atomic_rollback_on_invalid_signature():
    registry = ThreatIntelRegistry()
    initial_count = len(registry._signatures)
    initial_sig_keys = set(registry._signatures.keys())

    # Feed containing 2 valid signatures followed by 1 invalid regex
    corrupted_feed = {
        "sha256": None,
        "signatures": [
            {
                "id": "SIG-TEST-001",
                "pattern": r"valid\s+attack\s+pattern",
                "category": "DIRECT_INJECTION",
                "severity": "HIGH",
            },
            {
                "id": "SIG-TEST-002",
                "pattern": r"another\s+valid\s+pattern",
                "category": "DIRECT_INJECTION",
                "severity": "HIGH",
            },
            {
                "id": "SIG-CORRUPTED-003",
                "pattern": r"invalid(unclosed_regex_parenthesis[a-z+",  # Invalid regex syntax
                "category": "CORRUPTED",
                "severity": "CRITICAL",
            },
        ],
        "prohibited_tools": ["staged_tool_1"],
    }

    feed_json = json.dumps(corrupted_feed)

    # Must raise ValueError
    with pytest.raises(ValueError):
        registry.import_feed_json(feed_json)

    # State must be completely unmodified (atomic all-or-nothing guarantee)
    assert len(registry._signatures) == initial_count
    assert set(registry._signatures.keys()) == initial_sig_keys
    assert "SIG-TEST-001" not in registry._signatures
    assert "SIG-TEST-002" not in registry._signatures
    assert "staged_tool_1" not in registry._custom_prohibited_tools


def test_threat_intel_rejects_overlong_pattern():
    registry = ThreatIntelRegistry()
    overlong_pattern = "a" * 600

    with pytest.raises(ValueError) as exc_info:
        registry.register_signature("SIG-LONG", overlong_pattern)

    assert "exceeds maximum allowed length" in str(exc_info.value).lower()
