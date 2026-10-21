# 🔌 Standalone Model Context Protocol (MCP) Security Gateway

LightGuard-Agent v0.5.0 provides a standalone **JSON-RPC 2.0 Security Gateway** (`lightguard-mcp`) that can wrap any upstream MCP server with zero code changes.

It intercepts tool calls and resources, sanitizes outputs before they reach the model, and halts unauthorized high-stakes actions in under **0.2ms**.

---

## 🚀 Desktop Client Integration

Add LightGuard as an inline proxy inside `claude_desktop_config.json` or Cursor IDE `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "lightguard-mcp",
      "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/allowed/workspace"]
    }
  }
}
```

---

## 💻 CLI Usage

Wrap any Python or Node.js MCP server directly from the command line:

```bash
lightguard-mcp -- python my_mcp_server.py
```
