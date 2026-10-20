import dataclasses
import enum
import json
from typing import Any


class PolicyProfile(str, enum.Enum):
    STRICT = "strict"          # Financial, medical, high-security infrastructure
    BALANCED = "balanced"      # Standard production deployment (Default)
    PERMISSIVE = "permissive"  # Telemetry, auditing, monitoring mode (no active blocks)


@dataclasses.dataclass
class SecurityPolicyConfig:
    profile: PolicyProfile = PolicyProfile.BALANCED
    risk_threshold: float = 0.50
    block_on_untrusted: bool = True
    enable_obfuscation_shield: bool = True
    enable_canary_guard: bool = True
    enable_dlp_redaction: bool = False
    custom_high_stakes_tools: list[str] = dataclasses.field(default_factory=list)
    whitelisted_tools: list[str] = dataclasses.field(default_factory=list)

    @classmethod
    def strict(cls) -> "SecurityPolicyConfig":
        """Pre-configured high-security profile."""
        return cls(
            profile=PolicyProfile.STRICT,
            risk_threshold=0.35,
            block_on_untrusted=True,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=True,
        )

    @classmethod
    def balanced(cls) -> "SecurityPolicyConfig":
        """Default balanced production profile."""
        return cls(
            profile=PolicyProfile.BALANCED,
            risk_threshold=0.50,
            block_on_untrusted=True,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=False,
        )

    @classmethod
    def permissive(cls) -> "SecurityPolicyConfig":
        """Observability and auditing only profile; flags without blocking."""
        return cls(
            profile=PolicyProfile.PERMISSIVE,
            risk_threshold=0.70,
            block_on_untrusted=False,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=False,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityPolicyConfig":
        profile_str = data.get("profile", "balanced").lower()
        try:
            profile = PolicyProfile(profile_str)
        except ValueError:
            profile = PolicyProfile.BALANCED

        return cls(
            profile=profile,
            risk_threshold=float(data.get("risk_threshold", 0.50)),
            block_on_untrusted=bool(data.get("block_on_untrusted", True)),
            enable_obfuscation_shield=bool(data.get("enable_obfuscation_shield", True)),
            enable_canary_guard=bool(data.get("enable_canary_guard", True)),
            enable_dlp_redaction=bool(data.get("enable_dlp_redaction", False)),
            custom_high_stakes_tools=list(data.get("custom_high_stakes_tools", [])),
            whitelisted_tools=list(data.get("whitelisted_tools", [])),
        )

    @classmethod
    def from_json(cls, json_str_or_path: str) -> "SecurityPolicyConfig":
        """Loads configuration from JSON string or file path."""
        try:
            with open(json_str_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = json.loads(json_str_or_path)
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "risk_threshold": self.risk_threshold,
            "block_on_untrusted": self.block_on_untrusted,
            "enable_obfuscation_shield": self.enable_obfuscation_shield,
            "enable_canary_guard": self.enable_canary_guard,
            "enable_dlp_redaction": self.enable_dlp_redaction,
            "custom_high_stakes_tools": self.custom_high_stakes_tools,
            "whitelisted_tools": self.whitelisted_tools,
        }
