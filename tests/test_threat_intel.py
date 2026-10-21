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
    secret_key = "corp-intel-secret-key-2026"
    exported_json = registry.export_feed_json(sign_hmac_key=secret_key)

    # 1. Direct import without stripping keys (canonical hash verification)
    new_registry = ThreatIntelRegistry()
    added = new_registry.import_feed_json(exported_json, verify_hmac_key=secret_key)
    assert added >= 1
    assert "internal_secret_endpoint" in new_registry.get_all_patterns()

    # 2. HMAC tampering detection
    tampered_json = exported_json.replace("internal_secret_endpoint", "malicious_override")
    with pytest.raises(ValueError, match="checksum mismatch|HMAC signature"):
        new_registry.import_feed_json(tampered_json, verify_hmac_key=secret_key)


def test_threat_intel_checksum_mismatch():
    registry = ThreatIntelRegistry()
    payload = json.dumps({"signatures": []})
    with pytest.raises(ValueError, match="Threat intelligence checksum mismatch"):
        registry.import_feed_json(payload, verify_checksum="invalid_sha256_hash")


def test_threat_intel_pattern_validation_and_redos_protection():
    registry = ThreatIntelRegistry()

    # 1. Invalid regex syntax must be rejected at registration
    with pytest.raises(ValueError, match="Invalid regex syntax"):
        registry.register_signature("INVALID-01", r"[unclosed_bracket")

    # 2. Excessively long pattern (>1000 chars) must be rejected
    long_pattern = "a" * 1005
    with pytest.raises(ValueError, match="exceeds maximum limit"):
        registry.register_signature("TOO-LONG-01", long_pattern)

    # 3. Dangerous nested quantifiers susceptible to ReDoS must be rejected
    with pytest.raises(ValueError, match="susceptible to ReDoS"):
        registry.register_signature("REDOS-01", r"([a-z]+)+$")
