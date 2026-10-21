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

    def __init__(self, guard: Optional[LightGuardAgent] = None):
        self.guard = guard if guard is not None else LightGuardAgent()
        self.proxy = LightGuardMCPProxy(guard=self.guard)

    def process_client_to_server(self, raw_message: str) -> Tuple[bool, str]:
        """Inspect client requests before sending to the MCP server.

        Returns (allowed, forwarded_or_error_message).
        """
        try:
            req = json.loads(raw_message)
        except Exception:
            return True, raw_message

        # Safely handle non-dict JSON (e.g. JSON arrays or primitives)
        if not isinstance(req, dict):
            return True, raw_message

        method = req.get("method", "")
        req_id = req.get("id")

        if method == "tools/call":
            params = req.get("params")
            if not isinstance(params, dict):
                params = {}
            tool_name = params.get("name", "")
            tool_args = params.get("arguments")
            if not isinstance(tool_args, dict):
                tool_args = {}

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
            return True, raw_message

        if not isinstance(resp, dict):
            return True, raw_message

        result = resp.get("result")
        if not isinstance(result, dict):
            return True, raw_message

        modified = False

        # 1. Standard tool execution content: result.content
        content_items = result.get("content")
        if isinstance(content_items, list):
            for item in content_items:
                if isinstance(item, dict):
                    if item.get("type") == "text" and isinstance(item.get("text"), str):
                        raw_text = item["text"]
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


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_stdio_gateway(sys.argv[1:])
    else:
        print("Usage: python -m lightguard.mcp_gateway <upstream_mcp_command> [args...]")
        sys.exit(1)
