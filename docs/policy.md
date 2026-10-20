# ⚙️ Security Policy Profiles

Enterprise AI deployments require configurable risk tolerances. What is considered an acceptable tool invocation in a read-only support bot might be unacceptable in a financial trading agent.

`SecurityPolicyConfig` provides three out-of-the-box profiles and granular per-tool permissions.

---

## 🛡️ Pre-Configured Profiles

| Profile | Semantic Threshold | Canary Check | DLP / PII | Default High-Stakes Blocked | Recommended Use Case |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`STRICT`** | `0.30` | ✅ Yes | ✅ Yes | All database, filesystem, execution tools | Production, Financial, Autonomous Agents |
| **`BALANCED`** | `0.50` | ✅ Yes | ✅ Yes | Dangerous destructive tools | General Enterprise Agents, Chatbots |
| **`PERMISSIVE`** | `0.80` | ❌ No | ❌ No | Explicit user-defined blacklist only | Dev/Test environments, internal sandboxes |

---

## 🚀 Quick Example

```python
from lightguard import LightGuardAgent, SecurityPolicyConfig, PolicyProfile

# Instantiate with STRICT enterprise profile
policy = SecurityPolicyConfig.from_profile(PolicyProfile.STRICT)

# Customize specific tool permissions
policy.custom_high_stakes.add("execute_kubernetes_pod")
policy.whitelisted_tools.add("get_system_time")

agent = LightGuardAgent(policy=policy)
```

---

## 📋 JSON Configuration

Load and serialize policies for CI/CD or runtime configuration:

```python
# Export to dictionary
config_dict = policy.to_dict()

# Load from JSON or dictionary
custom_policy = SecurityPolicyConfig.from_dict({
    "profile": "STRICT",
    "semantic_threshold": 0.25,
    "enable_dlp": True,
    "enable_canary": True,
    "whitelisted_tools": ["safe_read"]
})
```
