# Framework Integrations

LightGuard-Agent integrates seamlessly with major agent frameworks: **LangChain**, **LangGraph**, **CrewAI**, and **LlamaIndex**.

---

## 1. LangChain & LangGraph

Use `LightGuardCallbackHandler` to guard tool execution in LangChain agents:

```python
from lightguard.integrations.langchain import LightGuardCallbackHandler
from langchain.agents import create_openai_tools_agent, AgentExecutor

guard_handler = LightGuardCallbackHandler()

agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[guard_handler]
)

response = agent_executor.invoke({"input": "Summarize the latest document"})
```

The handler automatically intercepts:
- `on_tool_start`: blocks unauthorized tool invocations or credential leaks.
- `on_tool_end`: sanitizes untrusted tool outputs before they reach the LLM.

---

## 2. CrewAI

Secure your CrewAI agents or tools using `secure_crew` or `protect_crew_tool`:

```python
from crewai import Agent, Crew
from lightguard.integrations.crewai import secure_crew

researcher = Agent(
    role="Web Researcher",
    goal="Gather technical documents",
    tools=[search_tool, scrape_tool],
    verbose=True
)

# Secure all tools attached to the agent
secure_crew(researcher)
```

---

## 3. LlamaIndex

Protect RAG query engines and document retrievers against document poisoning:

```python
from llama_index.core import VectorStoreIndex
from lightguard.integrations.llamaindex import protect_query_engine

index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

# Secure query engine against poisoned context chunks
secured_engine = protect_query_engine(query_engine)

response = secured_engine.query("What are the quarterly projections?")
```
