import json

import pytest

from lightguard.threat_intel import ThreatIntelRegistry


def test_threat_intel_baseline():
    registry = ThreatIntelRegistry()
    assert registry.total_signatures >= 6
    patterns = registry.get_all_patterns()
    assert any("ignore" in p for p in patterns)


def test_threat_intel_register_custom():
    registry = ThreatIntelRegistry()
    initial_count = registry.total_signatures
    registry.register_signature(
        signature_id="CUSTOM-001",
        pattern=r"override\s+security\s+kernel",
        category="KERNEL_ATTACK",
        severity="CRITICAL",
        description="Attempts to override security kernel",
    )
    assert registry.total_signatures == initial_count + 1
    assert "override\\s+security\\s+kernel" in registry.get_all_patterns()


def test_threat_intel_export_import_verified():
    registry = ThreatIntelRegistry()
    registry.register_signature("ENTERPRISE-99", r"internal_secret_endpoint", "DATA_LEAK")
    exported_json = registry.export_feed_json()

    data = json.loads(exported_json)
    checksum = data["sha256"]
    del data["sha256"]
    raw_json = json.dumps(data, indent=2)

    new_registry = ThreatIntelRegistry()
    added = new_registry.import_feed_json(raw_json, verify_checksum=checksum)
    assert added >= 1


def test_threat_intel_checksum_mismatch():
    registry = ThreatIntelRegistry()
    payload = json.dumps({"signatures": []})
    with pytest.raises(ValueError, match="Threat intelligence checksum mismatch"):
        registry.import_feed_json(payload, verify_checksum="invalid_sha256_hash")
