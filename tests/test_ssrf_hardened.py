import socket
from unittest.mock import patch

from lightguard.core import LightGuardAgent
from lightguard.policy import SecurityPolicyConfig
from lightguard.structured import StructuredOutputGuard


def test_ssrf_blocked_integer_and_hex_ips():
    guard = LightGuardAgent()
    struct_guard = StructuredOutputGuard(guard=guard)

    # 127.0.0.1 as dword integer (2130706433)
    err = struct_guard.validate_url_ssrf("http://2130706433/admin")
    assert err is not None
    assert "SSRF" in err or "blocked" in err

    # 169.254.169.254 as dword integer (2852039166)
    err_meta = struct_guard.validate_url_ssrf("http://2852039166/latest/meta-data")
    assert err_meta is not None
    assert "SSRF" in err_meta or "metadata" in err_meta or "blocked" in err_meta

    # 127.0.0.1 as hex (0x7f000001)
    err_hex = struct_guard.validate_url_ssrf("http://0x7f000001/status")
    assert err_hex is not None
    assert "SSRF" in err_hex or "blocked" in err_hex


def test_ssrf_blocked_ipv6_mapped_and_loopback():
    guard = LightGuardAgent()
    struct_guard = StructuredOutputGuard(guard=guard)

    # IPv4-mapped IPv6 ::ffff:127.0.0.1
    err_map = struct_guard.validate_url_ssrf("http://[::ffff:127.0.0.1]/secret")
    assert err_map is not None
    assert "SSRF" in err_map or "blocked" in err_map

    # IPv6 Loopback [::1]
    err_loop = struct_guard.validate_url_ssrf("http://[::1]/debug")
    assert err_loop is not None
    assert "SSRF" in err_loop or "internal" in err_loop or "loopback" in err_loop


def test_ssrf_dns_resolution_blocks_private_ip():
    guard = LightGuardAgent()
    struct_guard = StructuredOutputGuard(guard=guard)

    # Mock DNS returning 192.168.1.50 for innocent-looking domain
    def mock_getaddrinfo(host, port, *args, **kwargs):
        if host == "webhook.internal.corp":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 80))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
        # Should be blocked because resolved IP is RFC 1918 private
        err = struct_guard.validate_url_ssrf("http://webhook.internal.corp/callback")
        assert err is not None
        assert "192.168.1.50" in err or "SSRF" in err

        # Public IP should pass
        ok = struct_guard.validate_url_ssrf("http://example.com/api")
        assert ok is None


def test_ssrf_policy_allowed_url_schemes():
    # Only https allowed
    policy = SecurityPolicyConfig(allowed_url_schemes=["https"])
    guard = LightGuardAgent(policy=policy)
    struct_guard = StructuredOutputGuard(guard=guard)

    # http should be rejected
    err_http = struct_guard.validate_url_ssrf("http://example.com/api")
    assert err_http is not None
    assert "only https" in err_http.lower() or "scheme 'http'" in err_http.lower()

    # file:// should be rejected
    err_file = struct_guard.validate_url_ssrf("file:///etc/passwd")
    assert err_file is not None
    assert "scheme" in err_file.lower()
