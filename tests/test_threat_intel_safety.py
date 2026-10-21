import json

import pytest

from lightguard.threat_intel import ThreatIntelRegistry


def test_register_signature_rejects_invalid_regex():
    registry = ThreatIntelRegistry()
    with pytest.raises(ValueError) as exc_info:
        registry.register_signature("SIG-INV-1", "[unclosed_bracket(")
    assert "invalid regex" in str(exc_info.value).lower()


def test_register_signature_rejects_excessive_length():
    registry = ThreatIntelRegistry()
    huge_pattern = "a" * 1500
    with pytest.raises(ValueError) as exc_info:
        registry.register_signature("SIG-HUGE", huge_pattern)
    assert "maximum limit" in str(exc_info.value).lower()


def test_import_feed_requires_hmac_when_key_supplied():
    registry = ThreatIntelRegistry()
    unsigned_feed = json.dumps({
        "signatures": [{"id": "TEST-1", "pattern": "attack_keyword"}]
    })
    # Caller supplies verify_hmac_key expecting publisher authentication, but feed is unsigned
    with pytest.raises(ValueError) as exc_info:
        registry.import_feed_json(unsigned_feed, verify_hmac_key="supersecret")
    assert "hmac" in str(exc_info.value).lower()
    assert "lacks" in str(exc_info.value).lower() or "missing" in str(exc_info.value).lower()


def test_import_feed_rejects_invalid_regex_in_feed():
    registry = ThreatIntelRegistry()
    bad_feed = json.dumps({
        "signatures": [{"id": "TEST-BAD", "pattern": "([a-z"}]
    })
    with pytest.raises(ValueError) as exc_info:
        registry.import_feed_json(bad_feed)
    assert "invalid regex" in str(exc_info.value).lower()
