# 🛡️ Structured Output & Function Calling Guard

When AI agents output structured function call arguments, attackers can attempt:
1. **JSON Parameter Smuggling:** Embedding prompt injection directives inside JSON string fields.
2. **Path Traversal:** Injecting `../` or `/etc/passwd` into file path parameters.
3. **Command Chaining:** Injecting `;`, `&&`, or backticks into shell execution arguments.

`StructuredOutputGuard` validates structured arguments before tool execution.

---

## 🚀 Quick Example

```python
from lightguard import StructuredOutputGuard

guard = StructuredOutputGuard()

validation = guard.validate_tool_arguments(
    tool_name="read_file",
    arguments={"path": "../../etc/shadow"}
)

if not validation["allowed"]:
    print("Action Blocked:", validation["violations"])
```
