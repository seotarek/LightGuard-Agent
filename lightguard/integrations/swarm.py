"""Multi-Agent Swarm Lateral Injection Shield.

Protects multi-agent frameworks (CrewAI, AutoGen, LangGraph Swarms) against
Lateral Prompt Injection (LPI) and Agent-to-Agent Privilege Escalation, where
an infected worker agent attempts to compromise a higher-privilege executor agent.
"""

import time
from typing import Any, Dict, List, Optional, Set

from lightguard.core import LightGuardAgent


class AgentTaintTracker:
    """Tracks infection/taint states across agents in an autonomous swarm."""

    def __init__(self) -> None:
        self._tainted_agents: Dict[str, float] = {}
        self._taint_reasons: Dict[str, str] = {}

    def taint_agent(self, agent_id: str, reason: str) -> None:
        """Mark an agent as compromised or operating on untrusted data."""
        self._tainted_agents[agent_id] = time.time()
        self._taint_reasons[agent_id] = reason

    def is_tainted(self, agent_id: str) -> bool:
        """Return True if agent is tainted."""
        return agent_id in self._tainted_agents

    def clear_taint(self, agent_id: str) -> None:
        """Clear taint state for an agent after sanitized reset."""
        self._tainted_agents.pop(agent_id, None)
        self._taint_reasons.pop(agent_id, None)

    def get_taint_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        if agent_id in self._tainted_agents:
            return {
                "tainted": True,
                "timestamp": self._tainted_agents[agent_id],
                "reason": self._taint_reasons.get(agent_id, "Untrusted observation"),
            }
        return None


class MultiAgentSwarmShield:
    """Inter-agent firewall preventing lateral prompt injection across agent swarms."""

    def __init__(
        self,
        guard: Optional[LightGuardAgent] = None,
        high_privilege_roles: Optional[Set[str]] = None,
    ) -> None:
        self.guard = guard if guard is not None else LightGuardAgent()
        self.taint_tracker = AgentTaintTracker()
        self.high_privilege_roles = high_privilege_roles or {
            "coder",
            "executor",
            "admin",
            "database_manager",
            "bash_agent",
            "root",
        }
        self._event_log: List[Dict[str, Any]] = []

    def record_agent_observation(
        self,
        agent_id: str,
        raw_observation: str,
    ) -> Dict[str, Any]:
        """Record and sanitize external tool output received by an agent."""
        res = self.guard.process_observation(raw_observation)
        if res["is_untrusted"]:
            self.taint_tracker.taint_agent(
                agent_id,
                reason=f"Ingested untrusted observation: {res['threat_categories']}",
            )
        return res

    def inspect_inter_agent_message(
        self,
        sender_id: str,
        recipient_id: str,
        message: str,
        sender_role: str = "worker",
        recipient_role: str = "worker",
    ) -> Dict[str, Any]:
        """Intercept and sanitize messages exchanged between peer agents."""
        t0 = time.perf_counter()
        is_sender_tainted = self.taint_tracker.is_tainted(sender_id)
        is_recipient_high_priv = recipient_role.lower() in self.high_privilege_roles

        # Scan message through LightGuard multi-tier core
        obs_res = self.guard.process_observation(message)
        contains_injection = obs_res["is_untrusted"]

        # Detect Lateral Privilege Escalation (Tainted worker -> High privilege executor)
        escalation_threat = is_sender_tainted and is_recipient_high_priv
        quarantined = contains_injection or escalation_threat

        clean_message = obs_res["clean_text"]
        if quarantined:
            # If quarantined, wrap in explicit warning boundary
            sanitized = (
                f"<untrusted_peer_message sender='{sender_id}' tainted='true'>\n"
                f"{clean_message}\n"
                f"</untrusted_peer_message>"
            )
        else:
            sanitized = clean_message

        latency_ms = (time.perf_counter() - t0) * 1000.0

        verdict = {
            "allowed": not contains_injection,
            "quarantined": quarantined,
            "lateral_escalation_detected": escalation_threat,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "sanitized_message": sanitized,
            "risk_score": obs_res["risk_score"],
            "threats": obs_res["threat_categories"],
            "latency_ms": latency_ms,
        }

        self._event_log.append(verdict)
        return verdict

    def get_event_log(self) -> List[Dict[str, Any]]:
        """Return history of all inspected inter-agent interactions."""
        return list(self._event_log)
