"""Tests for DLP, Extended Secret Detection & Structured Redaction."""

from lightguard.privacy import PrivacyGuard


def test_extended_secret_detection_google_hf_stripe():
    # Google Cloud API key
    google_key = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
    res_google = PrivacyGuard.redact(f"My GCP key is {google_key}")
    assert google_key not in res_google.redacted_text
    assert any("GCP" in k or "GOOGLE" in k for k in res_google.entity_map.keys())

    # HuggingFace Token
    hf_token = "hf_AbCdEf1234567890abcdef1234567890ab"
    res_hf = PrivacyGuard.redact(f"HuggingFace token: {hf_token}")
    assert hf_token not in res_hf.redacted_text
    assert any("HUGGINGFACE" in k or "HF" in k for k in res_hf.entity_map.keys())

    # Stripe Secret Key
    stripe_key = "sk_test_51Abcdefghijklmnop1234567890"
    res_stripe = PrivacyGuard.redact(f"Stripe secret: {stripe_key}")
    assert stripe_key not in res_stripe.redacted_text
    assert any("STRIPE" in k for k in res_stripe.entity_map.keys())



def test_structured_data_redaction():
    complex_payload = {
        "user": {
            "name": "Alice Smith",
            "email": "alice@corp.example.com",
            "contact": {
                "phone": "+1-555-123-4567",
                "notes": "Emergency key: sk-ant-api03-abcdef1234567890abcdef1234567890",
            },
        },
        "tags": ["prod", "admin@internal.net"],
    }

    redacted_data, mapping, ms = PrivacyGuard.redact_structured(complex_payload)

    # Validate that emails and phones in nested dictionaries and lists are redacted
    assert "alice@corp.example.com" not in str(redacted_data)
    assert "+1-555-123-4567" not in str(redacted_data)
    assert "admin@internal.net" not in str(redacted_data)
    assert len(mapping) >= 3

    # Validate that original values are recoverable
    restored_data = PrivacyGuard.restore_structured(redacted_data, mapping)
    assert restored_data["user"]["email"] == "alice@corp.example.com"
    assert restored_data["user"]["contact"]["phone"] == "+1-555-123-4567"
    assert restored_data["tags"][1] == "admin@internal.net"


def test_canary_guard_ttl_and_eviction():
    import time

    from lightguard.canary import CanaryGuard

    guard = CanaryGuard(max_canaries=3, ttl_seconds=0.1)
    c1 = guard.generate_canary("test1")
    c2 = guard.generate_canary("test2")
    c3 = guard.generate_canary("test3")
    assert guard.active_canaries_count == 3

    # Adding a 4th canary should evict oldest (c1) due to capacity limit
    c4 = guard.generate_canary("test4")
    assert guard.active_canaries_count == 3
    assert guard.check_leakage(c1)[0] is False
    assert guard.check_leakage(c2)[0] is True
    assert guard.check_leakage(c3)[0] is True
    assert guard.check_leakage(c4)[0] is True

    # Test TTL expiration after 0.15s
    time.sleep(0.15)
    guard._prune_expired()
    assert guard.active_canaries_count == 0

