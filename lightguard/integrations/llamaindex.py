from typing import Any, Optional

from lightguard.core import LightGuardAgent


def protect_query_engine(
    query_engine: Any,
    guard: Optional[LightGuardAgent] = None,
) -> Any:
    """Secures a LlamaIndex QueryEngine or Retriever against RAG / document poisoning.

    Sanitizes retrieved text chunks and node contents before passing to LLM synthesis.
    """
    agent_guard = guard if guard is not None else LightGuardAgent()

    if hasattr(query_engine, "query") and callable(getattr(query_engine, "query")):
        original_query = query_engine.query

        def secured_query(query_bundle: Any, **kwargs: Any) -> Any:
            response = original_query(query_bundle, **kwargs)

            # If response has source_nodes, sanitize each node's text
            if hasattr(response, "source_nodes") and isinstance(response.source_nodes, list):
                for node in response.source_nodes:
                    node_obj = getattr(node, "node", node)
                    if hasattr(node_obj, "text") and isinstance(node_obj.text, str):
                        sanitized = agent_guard.process_observation(node_obj.text)
                        node_obj.text = sanitized["sanitized_observation"]

            # If response is a direct string or string response
            if hasattr(response, "response") and isinstance(response.response, str):
                sanitized_resp = agent_guard.process_observation(response.response)
                response.response = sanitized_resp["sanitized_observation"]

            return response

        query_engine.query = secured_query

    return query_engine
