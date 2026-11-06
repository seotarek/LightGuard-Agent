import pytest

from lightguard.decorators import SecurityViolationError
from lightguard.structured import StructuredOutputGuard, pin_url_connection


def test_ssrf_fails_closed_on_unresolvable_hostname():
    guard = StructuredOutputGuard()

    # An intentionally non-existent domain name
    url = "http://this-domain-definitely-does-not-exist-xyz123987.org/test"
    err = guard.validate_url_ssrf(url)

    assert err is not None
    assert "dns resolution failed" in err.lower() or "unresolvable" in err.lower()


def test_ssrf_blocks_cloud_metadata_ipv6_variants():
    guard = StructuredOutputGuard()

    # IPv6 AWS metadata address
    url = "http://[fd00:ec2::254]/latest/meta-data/"
    err = guard.validate_url_ssrf(url)
    assert err is not None
    assert "metadata" in err.lower() or "blocked" in err.lower()


def test_connection_pinning_helper():
    # Valid domain (localhost or resolved)
    url = "http://127.0.0.1/api"
    # Should be blocked because it resolves to loopback
    with pytest.raises(SecurityViolationError, match="SSRF"):
        pin_url_connection(url)


def test_connection_pinning_helper_unresolvable():
    url = "http://unresolvable-fake-host-999.invalid/api"
    with pytest.raises(SecurityViolationError, match="DNS resolution failed|unresolvable"):
        pin_url_connection(url)
