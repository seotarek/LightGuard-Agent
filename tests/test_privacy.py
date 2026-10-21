from lightguard.privacy import PrivacyGuard


def test_luhn_algorithm_validation():
    # Valid Visa card candidate (test pattern with valid Luhn)
    valid_card = "4532015112830366"
    assert PrivacyGuard.validate_luhn(valid_card) is True

    # Invalid card number
    invalid_card = "4532015112830367"
    assert PrivacyGuard.validate_luhn(invalid_card) is False

    # Short numbers should fail
    assert PrivacyGuard.validate_luhn("12345") is False


def test_scan_and_redact_secrets():
    text = (
        "Here is my OpenAI key: sk-abcdefghijklmnopqrstuvwxyz1234567890\n"
        "And AWS Key: AKIAIOSFODNN7EXAMPLE\n"
        "And GitHub token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    )
    detections = PrivacyGuard.scan(text)
    assert len(detections) >= 3

    types = {d.entity_type for d in detections}
    assert "OPENAI_KEY" in types
    assert "AWS_KEY_ID" in types
    assert "GITHUB_TOKEN" in types

    redacted, mapping, elapsed_ms = PrivacyGuard.redact(text, reversible=True)
    assert "sk-" not in redacted
    assert "AKIA" not in redacted
    assert "ghp_" not in redacted
    assert elapsed_ms < 2.0

    # Test restoration
    restored = PrivacyGuard.restore(redacted, mapping)
    assert restored == text


def test_scan_and_redact_pii():
    text = (
        "Contact me at alice@company.org or phone 415-555-2671. "
        "User SSN is 000-12-3456 and server IP is 192.168.1.50."
    )
    redacted, mapping, _ = PrivacyGuard.redact(text, reversible=True)
    assert "alice@company.org" not in redacted
    assert "000-12-3456" not in redacted
    assert "192.168.1.50" not in redacted

    restored = PrivacyGuard.restore(redacted, mapping)
    assert restored == text


def test_scan_and_redact_multilength_credit_cards():
    # 15-digit Amex test card with valid Luhn
    amex_card = "378282246310005"
    assert PrivacyGuard.validate_luhn(amex_card) is True

    # 16-digit Visa
    visa_card = "4532-0151-1283-0366"
    assert PrivacyGuard.validate_luhn(visa_card) is True

    # 14-digit Diners Club test card with valid Luhn (30000000000004 -> sum is valid)
    diners_card = "30000000000004"
    assert PrivacyGuard.validate_luhn(diners_card) is True

    text = f"Payment methods: Amex {amex_card}, Visa {visa_card}, Diners {diners_card}."
    redacted, mapping, _ = PrivacyGuard.redact(text, reversible=True)

    assert amex_card not in redacted
    assert visa_card not in redacted
    assert diners_card not in redacted
    assert len(mapping) == 3

    restored = PrivacyGuard.restore(redacted, mapping)
    assert restored == text

