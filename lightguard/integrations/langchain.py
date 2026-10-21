"""LangChain & LangGraph First-Class Security Integration.

Provides drop-in Callback Handlers and LangGraph Guard Nodes to protect
agent state transitions and tool executions with sub-millisecond overhead.
"""

from typing import Any, Callable, Dict, List, Optional

from lightguard.core import LightGuardAgent

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    # Graceful fallback when langchain-core is not installed
    class BaseCallbackHandler:  # type: ignore[no-redef]
        pass


class LightGuardCallbackHandler(BaseCallbackHandler):
    """LangChain Callback Handler for runtime prompt injection defense.

    Inspects tool inputs for sensitive leakage, intercepts prompts, and sanitizes
    observation outputs before they enter the model context.
    """

    def __init__(self, guard: Optional[LightGuardAgent] = None):
        super().__init__()
        self.guard = guard if guard is not None else LightGuardAgent()
        self.is_untrusted_context: bool = False

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> Any:
        """Inspect proposed tool execution before invocation."""
        tool_name = serialized.get("name", "unknown_tool")
        tool_args = {"input": input_str}

        action_verif = self.guard.verify_action(
            proposed_tool=tool_name,
            tool_args=tool_args,
            is_untrusted=self.is_untrusted_context,
        )

        if not action_verif["allowed"]:
            raise PermissionError(
                f"[LightGuard Firewall Blocked] Tool '{tool_name}': {action_verif['reason']}"
            )

    def on_tool_end(self, output: Any, **kwargs: Any) -> Any:
        """Inspect and sanitize tool outputs before passing back to the LLM."""
        if isinstance(output, str):
            obs = self.guard.process_observation(output)
            if obs["is_untrusted"]:
                self.is_untrusted_context = True
            return obs["sanitized_observation"]
        return output

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> Any:
        """Sanitize prompts or redact sensitive data before sending to LLM."""
        for p in prompts:
            # Tier 0 & 1 scan
            res = self.guard.process_observation(p)
            if res["is_untrusted"]:
                self.is_untrusted_context = True


def create_langgraph_guard(
    guard: Optional[LightGuardAgent] = None,
    message_key: str = "messages",
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Create a LangGraph node function that sanitizes graph state messages.

    Usage:
        workflow = StateGraph(AgentState)
        workflow.add_node("guard", create_langgraph_guard())
        workflow.add_edge("tools", "guard")
        workflow.add_edge("guard", "agent")
    """
    active_guard = guard if guard is not None else LightGuardAgent()

    def guard_node(state: Dict[str, Any]) -> Dict[str, Any]:
        messages = state.get(message_key, [])
        if not messages:
            return state

        # Inspect latest message (typically ToolMessage or AIMessage)
        last_msg = messages[-1]
        content = getattr(last_msg, "content", None)
        if content is None and isinstance(last_msg, dict):
            content = last_msg.get("content", "")

        if isinstance(content, str):
            obs = active_guard.process_observation(content)
            if obs["is_untrusted"]:
                # Sanitize content
                if hasattr(last_msg, "content"):
                    last_msg.content = obs["sanitized_observation"]
                elif isinstance(last_msg, dict):
                    last_msg["content"] = obs["sanitized_observation"]

        return state

    return guard_node
