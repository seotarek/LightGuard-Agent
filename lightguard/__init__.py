"""LightGuard-Agent: A Lightweight Defense Architecture Against Indirect Prompt Injection

in Tool-Calling AI Agents and Model Context Protocol (MCP) Workflows.

Author: Tarek Mohamed (seotarek@gmail.com)
"""

from .adversarial_suffix import AdversarialSuffixDetector
from .async_core import AsyncLightGuardAgent
from .bipia import BIPIABenchmarkReport, run_bipia_benchmark
from .canary import CanaryGuard, CanaryViolationError
from .core import (
    LightGuardAgent,
    Tier1SyntacticSanitizer,
    Tier2SemanticClassifier,
    Tier3ActionFirewall,
)
from .dashboard import run_dashboard
from .decorators import SecurityViolationError, protect_tool
from .fast_matcher import FastPatternMatcher
from .integrations.langchain import LightGuardCallbackHandler, create_langgraph_guard
from .integrations.swarm import AgentTaintTracker, MultiAgentSwarmShield
from .mcp import LightGuardMCPProxy
from .mcp_gateway import MCPGateway, MCPSecurityGateway
from .multimodal import MultimodalShield
from .obfuscation import Tier0ObfuscationShield
from .policy import PolicyProfile, SecurityPolicyConfig
from .privacy import PrivacyGuard, RedactionResult
from .rag import RAGContextShield
from .redteam import run_redteam_audit
from .reporting import ComplianceReportGenerator
from .session import StatefulSessionGuard
from .structured import StructuredOutputGuard
from .telemetry import SecurityTelemetryCollector
from .threat_intel import ThreatIntelRegistry, ThreatSignature
from .wrapper import wrap, wrap_client

__version__ = "0.6.3"
__all__ = [
    "LightGuardAgent",
    "run_bipia_benchmark",
    "BIPIABenchmarkReport",
    "AsyncLightGuardAgent",
    "FastPatternMatcher",
    "AdversarialSuffixDetector",
    "ThreatIntelRegistry",
    "ThreatSignature",
    "Tier0ObfuscationShield",
    "Tier1SyntacticSanitizer",
    "Tier2SemanticClassifier",
    "Tier3ActionFirewall",
    "CanaryGuard",
    "CanaryViolationError",
    "StatefulSessionGuard",
    "PrivacyGuard",
    "RedactionResult",
    "RAGContextShield",
    "SecurityPolicyConfig",
    "PolicyProfile",
    "SecurityTelemetryCollector",
    "MultiAgentSwarmShield",
    "AgentTaintTracker",
    "MCPSecurityGateway",
    "MCPGateway",
    "MultimodalShield",
    "StructuredOutputGuard",
    "ComplianceReportGenerator",
    "LightGuardCallbackHandler",
    "create_langgraph_guard",
    "protect_tool",
    "wrap",
    "wrap_client",
    "SecurityViolationError",
    "LightGuardMCPProxy",
    "run_redteam_audit",
    "run_dashboard",
]
