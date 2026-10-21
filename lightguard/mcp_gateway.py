"""Standalone Model Context Protocol (MCP) Security Gateway.

Intercepts JSON-RPC 2.0 communications between MCP clients (Claude Desktop,
Cursor, Zed) and upstream MCP servers, neutralizing indirect prompt injections
and blocking unauthorized high-stakes actions in real time (< 0.2ms).
"""

import json
import sys
from typing import Optional, Tuple

from lightguard.core import LightGuardAgent
from lightguard.mcp import LightGuardMCPProxy


class MCPSecurityGateway:
    """JSON-RPC 2.0 Security Proxy for Model Context Protocol."""

    def __init__(
        self,
        guard: Optional[LightGuardAgent] = None,
        max_message_size: int = 10 * 1024 * 1024,
    ):
        self.guard = guard if guard is not None else LightGuardAgent()
        self.proxy = LightGuardMCPProxy(guard=self.guard)
        self.max_message_size = max_message_size

    def process_client_to_server(self, raw_message: str) -> Tuple[bool, str]:
        """Inspect client requests before sending to the MCP server.

        Returns (allowed, forwarded_or_error_message).
        """
        if len(raw_message.encode("utf-8")) > self.max_message_size:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": f"Message size ({len(raw_message.encode('utf-8'))} bytes) exceeds limit ({self.max_message_size} bytes)",
                },
            }
            return False, json.dumps(err_resp)

        try:
            req = json.loads(raw_message)
        except Exception:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error: Invalid JSON payload rejected by LightGuard MCP Gateway",
                },
            }
            return False, json.dumps(err_resp)

        # Enforce JSON-RPC 2.0 specification: top-level payload must be a JSON object
        if not isinstance(req, dict):
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: JSON-RPC payload must be a JSON object",
                },
            }
            return False, json.dumps(err_resp)

        req_id = req.get("id")

        if req.get("jsonrpc") != "2.0":
            err_resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: JSON-RPC 'jsonrpc' field must be exactly '2.0'",
                },
            }
            return False, json.dumps(err_resp)

        method = req.get("method")
        if not isinstance(method, str) or not method.strip():
            err_resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: 'method' must be a non-empty string",
                },
            }
            return False, json.dumps(err_resp)

        if method == "tools/call":
            params = req.get("params")
            if not isinstance(params, dict):
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'params' must be a JSON object for tools/call",
                    },
                }
                return False, json.dumps(err_resp)

            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'params.name' must be a non-empty string tool name",
                    },
                }
                return False, json.dumps(err_resp)

            tool_name = tool_name.strip()
            tool_args = params.get("arguments")
            if tool_args is None:
                tool_args = {}
            elif not isinstance(tool_args, dict):
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'params.arguments' must be a JSON object",
                    },
                }
                return False, json.dumps(err_resp)

            validation = self.proxy.intercept_request(
                tool_name=tool_name,
                arguments=tool_args,
            )

            if not validation["allowed"]:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": f"LightGuard Security Violation: {validation['reason']}",
                        "data": {
                            "tool_name": tool_name,
                            "blocked_by": "LightGuard MCP Gateway",
                        },
                    },
                }
                return False, json.dumps(err_resp)

        return True, raw_message

    def process_server_to_client(self, raw_message: str) -> Tuple[bool, str]:
        """Inspect and sanitize server responses before returning to the LLM.

        Returns (is_clean, sanitized_message).
        """
        try:
            resp = json.loads(raw_message)
        except Exception:
            obs = self.guard.process_observation(raw_message)
            return not obs["is_untrusted"], obs["sanitized_observation"]

        if not isinstance(resp, dict):
            obs = self.guard.process_observation(raw_message)
            return not obs["is_untrusted"], obs["sanitized_observation"]

        result = resp.get("result")
        if not isinstance(result, dict):
            return True, raw_message

        modified = False

        # 0. Tool Capability Discovery: result.tools (from tools/list)
        tools_list = result.get("tools")
        if isinstance(tools_list, list):
            filtered_tools = []
            for tool_item in tools_list:
                if isinstance(tool_item, dict):
                    t_name = tool_item.get("name", "")
                    if t_name in self.guard.policy.denied_tools:
                        modified = True
                        continue
                    if self.guard.policy.allowed_tools and t_name not in self.guard.policy.allowed_tools:
                        modified = True
                        continue
                    filtered_tools.append(tool_item)
                else:
                    filtered_tools.append(tool_item)
            if modified:
                result["tools"] = filtered_tools

        # 1. Standard tool execution content: result.content
        content_items = result.get("content")
        if isinstance(content_items, list):
            for item in content_items:
                if isinstance(item, dict):
                    if item.get("type") == "text" and isinstance(item.get("text"), str):
                        raw_text = item["text"]
                        canary_leaked = False
                        if self.guard.policy.enable_canary_guard:
                            is_leaked, token = self.guard.canary.check_leakage(raw_text)
                            if is_leaked:
                                item["text"] = "[LightGuard Security Blocked: Secret canary leak detected in tool response]"
                                modified = True
                                self.proxy.session_is_untrusted = True
                                canary_leaked = True
                        if not canary_leaked:
                            obs = self.guard.process_observation(raw_text)
                            if obs["is_untrusted"]:
                                item["text"] = obs["sanitized_observation"]
                                modified = True
                                self.proxy.session_is_untrusted = True
                    elif item.get("type") == "resource" and isinstance(item.get("resource"), dict):
                        res_obj = item["resource"]
                        if isinstance(res_obj.get("text"), str):
                            obs = self.guard.process_observation(res_obj["text"])
                            if obs["is_untrusted"]:
                                res_obj["text"] = obs["sanitized_observation"]
                                modified = True
                                self.proxy.session_is_untrusted = True

        # 2. Resource read results: result.contents (from resources/read)
        contents_items = result.get("contents")
        if isinstance(contents_items, list):
            for item in contents_items:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    obs = self.guard.process_observation(item["text"])
                    if obs["is_untrusted"]:
                        item["text"] = obs["sanitized_observation"]
                        modified = True
                        self.proxy.session_is_untrusted = True

        # 3. Prompt messages: result.messages (from prompts/get)
        messages_items = result.get("messages")
        if isinstance(messages_items, list):
            for msg in messages_items:
                if isinstance(msg, dict):
                    msg_content = msg.get("content")
                    if isinstance(msg_content, str):
                        obs = self.guard.process_observation(msg_content)
                        if obs["is_untrusted"]:
                            msg["content"] = obs["sanitized_observation"]
                            modified = True
                            self.proxy.session_is_untrusted = True
                    elif isinstance(msg_content, dict) and msg_content.get("type") == "text":
                        raw_text = msg_content.get("text", "")
                        if isinstance(raw_text, str):
                            obs = self.guard.process_observation(raw_text)
                            if obs["is_untrusted"]:
                                msg_content["text"] = obs["sanitized_observation"]
                                modified = True
                                self.proxy.session_is_untrusted = True

        if modified:
            return False, json.dumps(resp)

        return True, raw_message

    def reset_session(self) -> None:
        """Reset the internal security proxy untrusted context state."""
        self.proxy.reset_session()


def run_stdio_gateway(upstream_cmd: list[str]) -> None:
    """Run an interactive bidirectional stdio proxy forwarding to upstream process."""
    import subprocess
    import threading

    gateway = MCPSecurityGateway()

    proc = subprocess.Popen(
        upstream_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    def forward_stdin():
        for line in sys.stdin:
            try:
                line_str = line.strip()
                if not line_str:
                    continue
                allowed, out = gateway.process_client_to_server(line_str)
                if allowed:
                    if proc.stdin:
                        proc.stdin.write(out + "\n")
                        proc.stdin.flush()
                else:
                    # Echo error back directly to client stdout
                    sys.stdout.write(out + "\n")
                    sys.stdout.flush()
            except Exception as e:
                sys.stderr.write(f"[LightGuard MCP] Inbound framing error: {e}\n")
                sys.stderr.flush()

    def forward_stdout():
        if not proc.stdout:
            return
        for line in proc.stdout:
            try:
                line_str = line.strip()
                if not line_str:
                    continue
                _, out = gateway.process_server_to_client(line_str)
                sys.stdout.write(out + "\n")
                sys.stdout.flush()
            except Exception as e:
                sys.stderr.write(f"[LightGuard MCP] Outbound framing error: {e}\n")
                sys.stderr.flush()

    t_in = threading.Thread(target=forward_stdin, daemon=True)
    t_out = threading.Thread(target=forward_stdout, daemon=True)
    t_in.start()
    t_out.start()

    proc.wait()


MCPGateway = MCPSecurityGateway


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_stdio_gateway(sys.argv[1:])
    else:
        print("Usage: python -m lightguard.mcp_gateway <upstream_mcp_command> [args...]")
        sys.exit(1)
