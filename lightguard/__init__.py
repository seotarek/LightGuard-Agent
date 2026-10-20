"""LightGuard-Agent: A Lightweight Defense Architecture Against Indirect Prompt Injection

in Tool-Calling AI Agents and Model Context Protocol (MCP) Workflows.

Author: Tarek Mohamed (seotarek@gmail.com)
"""

from .canary import CanaryGuard, CanaryViolationError
from .core import (
    LightGuardAgent,
    Tier1SyntacticSanitizer,
    Tier2SemanticClassifier,
    Tier3ActionFirewall,
)
from .decorators import SecurityViolationError, protect_tool
from .mcp import LightGuardMCPProxy
from .obfuscation import Tier0ObfuscationShield
from .policy import PolicyProfile, SecurityPolicyConfig
from .privacy import PrivacyGuard
from .rag import RAGContextShield
from .redteam import run_redteam_audit
from .session import StatefulSessionGuard
from .telemetry import SecurityTelemetryCollector
from .wrapper import wrap

__version__ = "0.4.1"
__all__ = [
    "LightGuardAgent",
    "Tier0ObfuscationShield",
    "Tier1SyntacticSanitizer",
    "Tier2SemanticClassifier",
    "Tier3ActionFirewall",
    "CanaryGuard",
    "CanaryViolationError",
    "StatefulSessionGuard",
    "PrivacyGuard",
    "RAGContextShield",
    "SecurityPolicyConfig",
    "PolicyProfile",
    "SecurityTelemetryCollector",
    "protect_tool",
    "wrap",
    "SecurityViolationError",
    "LightGuardMCPProxy",
    "run_redteam_audit",
]

