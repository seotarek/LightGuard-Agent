# Asynchronous Core (AsyncIO)

For high-throughput AI gateways, async tool loops, and modern web frameworks (FastAPI, aiohttp, Starlette), LightGuard-Agent provides native asynchronous bindings via `AsyncLightGuardAgent`.

---

## ⚡ Non-Blocking Execution

`AsyncLightGuardAgent` runs heavy regex compilation and syntactic transformations within an asynchronous thread pool executor, ensuring that the main event loop is never blocked.

---

## 🚀 FastAPI Integration Example

```python
from fastapi import FastAPI, HTTPException
from lightguard import AsyncLightGuardAgent

app = FastAPI()
guard = AsyncLightGuardAgent()

@app.post("/agent/execute")
async def execute_agent_step(observation: str, tool_name: str):
    # 1. Asynchronously sanitize untrusted input
    obs_res = await guard.process_observation(observation)
    
    # 2. Asynchronously verify proposed tool action
    act_res = await guard.verify_action(
        proposed_tool=tool_name,
        tool_args={"input": obs_res["sanitized_observation"]},
        is_untrusted=obs_res["is_untrusted"],
    )
    
    if not act_res["allowed"]:
        raise HTTPException(status_code=403, detail=act_res["reason"])
        
    return {
        "status": "success",
        "clean_observation": obs_res["sanitized_observation"],
        "action": tool_name,
    }
```
