from lightguard.audit import SecurityReasonCode
from lightguard.core import LightGuardAgent
from lightguard.policy import SecurityPolicyConfig


def test_resource_roots_permits_allowed_paths():
    policy = SecurityPolicyConfig(
        resource_roots=["/app/data", "/tmp/safe_zone"],
    )
    guard = LightGuardAgent(policy=policy)

    # Allowed path inside /app/data
    res1 = guard.verify_action(
        "read_file", {"path": "/app/data/reports/summary.csv"}, is_untrusted=False
    )
    assert res1["allowed"] is True

    # Allowed path inside /tmp/safe_zone
    res2 = guard.verify_action(
        "write_file", {"filepath": "/tmp/safe_zone/cache.json"}, is_untrusted=False
    )
    assert res2["allowed"] is True


def test_resource_roots_blocks_external_paths():
    policy = SecurityPolicyConfig(
        resource_roots=["/app/data"],
    )
    guard = LightGuardAgent(policy=policy)

    # Path outside /app/data (e.g. /etc/passwd or /var/secrets)
    res_outside = guard.verify_action(
        "read_file", {"path": "/var/secrets/app.key"}, is_untrusted=False
    )
    assert res_outside["allowed"] is False
    assert res_outside["reason_code"] in (
        SecurityReasonCode.LG_TOOL_PATH_TRAVERSAL.value,
        "LG_TOOL_RESOURCE_ROOT_VIOLATION",
    )
    assert (
        "resource_root" in res_outside["reason"].lower()
        or "outside" in res_outside["reason"].lower()
    )


def test_resource_roots_blocks_traversal_escape():
    policy = SecurityPolicyConfig(
        resource_roots=["/app/data"],
    )
    guard = LightGuardAgent(policy=policy)

    # Traversal attempting to escape from allowed root
    res_escape = guard.verify_action(
        "read_file", {"filepath": "/app/data/../../etc/shadow"}, is_untrusted=False
    )
    assert res_escape["allowed"] is False
