from typing import Any, Optional

from lightguard.core import LightGuardAgent

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    # Graceful fallback when langchain-core is not installed
    class BaseCallbackHandler:  # type: ignore[no-redef]
        pass


class LightGuardCallbackHandler(BaseCallbackHandler):
    """LangChain / LangGraph Callback Handler for runtime prompt injection defense.

    Inspects tool inputs for sensitive leakage and sanitizes observation outputs.
    """

    def __init__(self, guard: Optional[LightGuardAgent] = None):
        super().__init__()
        self.guard = guard if guard is not None else LightGuardAgent()
        self.is_untrusted_context: bool = False

    def on_tool_start(
        self,
        serialized: dict[str, Any],
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
