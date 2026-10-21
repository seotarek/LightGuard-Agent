from typing import Any, Optional

from lightguard.core import LightGuardAgent


class LightGuardMCPProxy:
    """Model Context Protocol (MCP) Security Middleware & Proxy.

    Intercepts MCP tool requests and tool execution results to enforce
    sub-millisecond prompt injection defenses and prevent unauthorized tool actions.
    """

    def __init__(self, guard: Optional[LightGuardAgent] = None):
        self.guard = guard if guard is not None else LightGuardAgent()
        self.has_untrusted_observation: bool = False

    @property
    def session_is_untrusted(self) -> bool:
        return self.has_untrusted_observation

    @session_is_untrusted.setter
    def session_is_untrusted(self, val: bool) -> None:
        self.has_untrusted_observation = bool(val)

    def reset_session(self) -> None:
        """Reset the conversation context state."""
        self.has_untrusted_observation = False

    def intercept_request(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate an outgoing MCP tool call before execution.

        Returns a dictionary with 'allowed' (bool), and if blocked,
        an MCP-compatible error payload.
        """
        verif = self.guard.verify_action(
            proposed_tool=tool_name,
            tool_args=arguments,
            is_untrusted=self.has_untrusted_observation,
        )

        if not verif["allowed"]:
            return {
                "allowed": False,
                "reason": verif["reason"],
                "mcp_error_response": {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"[LightGuard Security Firewall Blocked] {verif['reason']}",
                        }
                    ],
                },
            }

        return {"allowed": True, "reason": "Allowed"}

    def intercept_response(self, raw_output: str) -> dict[str, Any]:
        """Sanitize incoming data returned from an external MCP tool.

        Neutralizes delimiter attacks, wraps untrusted data, and flags session state.
        """
        obs = self.guard.process_observation(raw_output)

        if obs["is_untrusted"]:
            self.has_untrusted_observation = True

        return {
            "sanitized_content": obs["sanitized_observation"],
            "is_untrusted": obs["is_untrusted"],
            "t1_flagged": obs["t1_flagged"],
            "risk_score": obs["t2_risk_score"],
            "latency_ms": obs["total_latency_ms"],
        }
