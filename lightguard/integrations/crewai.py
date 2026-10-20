from typing import Any, Callable, Optional

from lightguard.core import LightGuardAgent
from lightguard.decorators import protect_tool


def protect_crew_tool(
    tool: Any,
    guard: Optional[LightGuardAgent] = None,
    block_on_untrusted: bool = True,
) -> Any:
    """Wraps a CrewAI BaseTool or tool function with LightGuard security.

    Sanitizes observation output and enforces action firewall execution policies.
    """
    agent_guard = guard if guard is not None else LightGuardAgent()

    # If it's a CrewAI BaseTool object with a _run method
    if hasattr(tool, "_run") and callable(getattr(tool, "_run")):
        original_run = tool._run
        tool_name = getattr(tool, "name", tool.__class__.__name__)

        @protect_tool(
            guard=agent_guard,
            tool_name=tool_name,
            block_on_untrusted=block_on_untrusted,
        )
        def secured_run(*args: Any, **kwargs: Any) -> Any:
            return original_run(*args, **kwargs)

        tool._run = secured_run
        return tool

    # If it's a direct callable / function
    if callable(tool):
        fn_name = getattr(tool, "__name__", "crew_tool")
        return protect_tool(
            tool,
            guard=agent_guard,
            tool_name=fn_name,
            block_on_untrusted=block_on_untrusted,
        )

    return tool


def secure_crew(
    crew_or_agent: Any,
    guard: Optional[LightGuardAgent] = None,
) -> Any:
    """Secures an entire CrewAI Agent or Crew by intercepting all associated tools."""
    agent_guard = guard if guard is not None else LightGuardAgent()

    # If it has agents list (a Crew instance)
    if hasattr(crew_or_agent, "agents"):
        for ag in crew_or_agent.agents:
            secure_crew(ag, guard=agent_guard)
        return crew_or_agent

    # If it is a single Agent instance with tools
    if hasattr(crew_or_agent, "tools") and isinstance(crew_or_agent.tools, list):
        crew_or_agent.tools = [
            protect_crew_tool(t, guard=agent_guard) for t in crew_or_agent.tools
        ]

    return crew_or_agent
