# Universal SDK Wrapper & Middleware

LightGuard-Agent v0.3.0 provides zero-code-change integration for modern LLM clients, web APIs, and agent pipelines.

---

## 1. Universal SDK Wrapper (`lightguard.wrap`)

Wrap standard LLM clients with 1 line of code. All incoming messages, system boundaries, and proposed tool calls are intercepted transparently:

```python
from openai import OpenAI
import lightguard

# Automatically wraps client.chat.completions.create
client = lightguard.wrap(OpenAI())

# Standard OpenAI call - fully protected against prompt injections
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a customer assistant."},
        {"role": "user", "content": "Please summarize this document."}
    ]
)
```

### Works With:
- `OpenAI` & `AsyncOpenAI`
- `Anthropic` (`anthropic.Anthropic`)
- `Groq` (`groq.Groq`)
- `Ollama`
- Custom Agent Callables: `safe_fn = lightguard.wrap(my_agent_function)`

---

## 2. FastAPI / Starlette Production Middleware

Add sub-millisecond inspection to your API endpoints before requests hit your controllers:

```python
from fastapi import FastAPI
from lightguard.middleware.fastapi import LightGuardASGIMiddleware

app = FastAPI(title="Secure AI Service")

# Intercepts POST/PUT payloads and returns 403 on prompt injection
app.add_middleware(
    LightGuardASGIMiddleware,
    block_on_violation=True,
    scan_paths=["/api/v1/agent", "/api/v1/chat"]
)

@app.post("/api/v1/chat")
async def chat_endpoint(data: dict):
    return {"status": "ok", "response": "Generated safe output"}
```

---

## 3. Flask / WSGI Middleware

```python
from flask import Flask, jsonify, request
from lightguard.middleware.flask import LightGuardFlaskMiddleware

app = Flask(__name__)
# Enable LightGuard WSGI firewall
LightGuardFlaskMiddleware(app, block_on_violation=True)

@app.route("/chat", methods=["POST"])
def chat():
    return jsonify({"status": "safe"})
```
