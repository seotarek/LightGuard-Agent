from lightguard.core import LightGuardAgent
from lightguard.policy import PolicyProfile, SecurityPolicyConfig


def test_policy_strict_profile():
    strict_policy = SecurityPolicyConfig.strict()
    assert strict_policy.profile == PolicyProfile.STRICT
    assert strict_policy.risk_threshold == 0.35
    assert strict_policy.enable_dlp_redaction is True

    agent = LightGuardAgent(policy=strict_policy)
    # PII should be redacted automatically under STRICT
    obs = agent.process_observation("My email is bob@corp.com")
    assert "bob@corp.com" not in obs["sanitized_observation"]
    assert obs["dlp_redacted"] is True


def test_policy_permissive_profile():
    permissive_policy = SecurityPolicyConfig.permissive()
    assert permissive_policy.block_on_untrusted is False

    agent = LightGuardAgent(policy=permissive_policy)
    # Permissive should NOT block execution even if context is untrusted
    act = agent.verify_action("send_email", {"to": "ext@domain.com"}, is_untrusted=True)
    assert act["allowed"] is True


def test_policy_custom_high_stakes_and_whitelist():
    policy = SecurityPolicyConfig(
        custom_high_stakes_tools=["restart_server", "terminate_instance"],
        whitelisted_tools=["exec_bash"],  # Whitelist override
    )
    agent = LightGuardAgent(policy=policy)

    # Custom high stakes tool blocked on untrusted
    act1 = agent.verify_action("restart_server", {}, is_untrusted=True)
    assert act1["allowed"] is False
    assert "designated as high-stakes by policy" in act1["reason"]

    # Whitelisted tool allowed even if untrusted
    act2 = agent.verify_action("exec_bash", {"cmd": "ls"}, is_untrusted=True)
    assert act2["allowed"] is True
    assert "Whitelisted tool" in act2["reason"]


def test_policy_from_dict_and_to_dict():
    cfg = SecurityPolicyConfig.from_dict({
        "profile": "strict",
        "risk_threshold": 0.25,
        "custom_high_stakes_tools": ["custom_tool"],
    })
    assert cfg.profile == PolicyProfile.STRICT
    assert cfg.risk_threshold == 0.25
    assert "custom_tool" in cfg.custom_high_stakes_tools

    d = cfg.to_dict()
    assert d["profile"] == "strict"
    assert d["risk_threshold"] == 0.25
