"""LightGuard-Agent: A Lightweight Defense Architecture Against Indirect Prompt Injection

in Tool-Calling AI Agents and Model Context Protocol (MCP) Workflows.

Author: Tarek Mohamed (seotarek@gmail.com)
"""

from .core import (
    LightGuardAgent,
    Tier1SyntacticSanitizer,
    Tier2SemanticClassifier,
    Tier3ActionFirewall,
)
from .decorators import SecurityViolationError, protect_tool
from .mcp import LightGuardMCPProxy

__version__ = "0.2.0"
__all__ = [
    "LightGuardAgent",
    "Tier1SyntacticSanitizer",
    "Tier2SemanticClassifier",
    "Tier3ActionFirewall",
    "protect_tool",
    "SecurityViolationError",
    "LightGuardMCPProxy",
]
