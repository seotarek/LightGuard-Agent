"""Tests for Deep Recursive Structured Argument & SSRF/Path Traversal Guard."""

from lightguard.structured import StructuredOutputGuard


def test_cyclic_argument_protection():
    guard = StructuredOutputGuard()
    # Create cyclic reference in dict
    cyclic_dict = {"a": 1}
    cyclic_dict["self"] = cyclic_dict

    res = guard.validate_tool_arguments("test_tool", cyclic_dict)
    assert not res["allowed"]
    assert any("cycl" in v.lower() for v in res["violations"])


def test_max_nesting_depth_limit():
    guard = StructuredOutputGuard()
    # Deeply nested structure (depth 15)
    deep_dict = {"leaf": "value"}
    for i in range(15):
        deep_dict = {"nested": deep_dict}

    res = guard.validate_tool_arguments("test_tool", deep_dict)
    assert not res["allowed"]
    assert any("depth" in v.lower() for v in res["violations"])


def test_ssrf_protection_in_urls():
    guard = StructuredOutputGuard()

    # AWS metadata endpoint
    res_aws = guard.validate_tool_arguments(
        "http_client",
        {"url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert not res_aws["allowed"]
    assert any("ssrf" in v.lower() or "metadata" in v.lower() for v in res_aws["violations"])

    # Localhost loopback
    res_local = guard.validate_tool_arguments(
        "http_client",
        {"target_url": "http://127.0.0.1:8080/admin"},
    )
    assert not res_local["allowed"]
    assert any("ssrf" in v.lower() or "loopback" in v.lower() or "internal" in v.lower() for v in res_local["violations"])

    # File scheme
    res_file = guard.validate_tool_arguments(
        "fetcher",
        {"webhook": "file:///etc/passwd"},
    )
    assert not res_file["allowed"]
    assert any("scheme" in v.lower() or "file" in v.lower() for v in res_file["violations"])

    # Legitimate external URL
    res_valid = guard.validate_tool_arguments(
        "http_client",
        {"url": "https://api.github.com/repos"},
    )
    assert res_valid["allowed"]


def test_sql_injection_detection():
    guard = StructuredOutputGuard()

    res_sqli = guard.validate_tool_arguments(
        "db_runner",
        {"query": "SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin--"},
    )
    assert not res_sqli["allowed"]
    assert any("sql" in v.lower() for v in res_sqli["violations"])

    res_drop = guard.validate_tool_arguments(
        "db_runner",
        {"sql": "SELECT 1; DROP TABLE users;"},
    )
    assert not res_drop["allowed"]
    assert any("sql" in v.lower() or "dangerous" in v.lower() for v in res_drop["violations"])


def test_path_traversal_across_all_string_keys():
    guard = StructuredOutputGuard()

    # Even if key is not named 'path', ../ is blocked
    res = guard.validate_tool_arguments(
        "custom_processor",
        {"data_source": "../../../etc/shadow"},
    )
    assert not res["allowed"]
    assert any("traversal" in v.lower() for v in res["violations"])
