#!/usr/bin/env python3
"""
DeepSeek ↔ Frappe Assistant Core Bridge

A terminal chat client that lets you use DeepSeek models to interact
with your ERPNext system through the Frappe Assistant Core MCP server.

Usage:
    python bridge.py --mcp-url https://your-site.com/api/method/.../handle_mcp \\
                     --api-key YOUR_FRAPPE_API_KEY \\
                     --api-secret YOUR_FRAPPE_API_SECRET

Or configure via environment variables:
    export FRAUD_ASSISTANT_MCP_URL="https://..."
    export FRAUD_ASSISTANT_API_KEY="..."
    export FRAUD_ASSISTANT_API_SECRET="..."
    export DEEPSEEK_API_KEY="sk-..."
    python bridge.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import readline  # noqa: F401 — enables line-editing and history in input()
import secrets
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

# Ctrl+C raises KeyboardInterrupt — works even during network calls
def _handle_interrupt(sig, frame):
    raise KeyboardInterrupt()

signal.signal(signal.SIGINT, _handle_interrupt)

import requests

# ---------------------------------------------------------------------------
# Rich is optional — degrade gracefully if not installed
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.markdown import Markdown

    console = Console()
    HAS_RICH = True
except ImportError:
    console = None  # type: ignore[assignment]
    HAS_RICH = False

try:
    from openai import OpenAI
except ImportError:
    print("Error: 'openai' package is required. Install with: pip install openai")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"
MAX_TOOL_ROUNDS = 25  # prevent infinite tool-calling loops
MCP_PROTOCOL_VERSION = "2025-06-18"
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".fac_bridge")
CONFIG_FILE = os.path.join(CONFIG_DIR, "sites.json")
SESSION_DIR = os.path.join(CONFIG_DIR, "sessions")
OAUTH_TIMEOUT = 120  # seconds to wait for browser login


# ---------------------------------------------------------------------------
# OAuth 2.0 flow — browser-based login (like Claude Desktop Connectors)
# ---------------------------------------------------------------------------
class OAuthFlow:
    """Handles OAuth 2.0 authorization code flow with PKCE for FAC sites."""

    @staticmethod
    def discover(base_url: str) -> Dict[str, str]:
        """Fetch OIDC discovery metadata from the Frappe site."""
        base = base_url.rstrip("/")
        # The base_url might be the full MCP endpoint path — extract the origin
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        discovery_url = f"{origin}/.well-known/openid-configuration"
        resp = requests.get(discovery_url, timeout=15)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def generate_pkce() -> Tuple[str, str]:
        """Generate PKCE code_verifier and code_challenge (S256). Returns (verifier, challenge)."""
        verifier = secrets.token_urlsafe(64)[:128]
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return verifier, challenge

    @staticmethod
    def find_free_port() -> int:
        """Find a free TCP port on localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


    @staticmethod
    def register_client(registration_url: str, redirect_uri: str) -> Dict[str, str]:
        """Register as an OAuth client via RFC 7591 dynamic registration."""
        payload = {
            "client_name": "DeepSeek FAC Bridge",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "all openid",
            "software_id": "deepseek-fac-bridge",
            "software_version": "1.0.0",
        }
        resp = requests.post(registration_url, json=payload, timeout=15)
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"OAuth client registration failed ({resp.status_code}): {resp.text[:300]}"
            )
        return resp.json()

    @classmethod
    def authorize(cls, fac_url: str) -> Dict[str, Any]:
        """
        Full OAuth authorization flow.

        Uses Frappe's callback endpoint as redirect_uri — no local server needed.
        The bridge polls for the code after the user approves in browser.
        """
        base = fac_url.rstrip("/")
        origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"

        # 1. Discover OAuth endpoints
        print("  Discovering OAuth endpoints…", end="\r")
        metadata = cls.discover(base)
        auth_endpoint = metadata["authorization_endpoint"]
        token_endpoint = metadata["token_endpoint"]
        registration_endpoint = metadata.get("registration_endpoint")
        print("  " + " " * 40, end="\r")

        # 2. Generate PKCE
        code_verifier, code_challenge = cls.generate_pkce()

        # 3. Use Frappe's callback endpoint as redirect_uri (works across setups)
        callback_url = f"{origin}/api/method/frappe_assistant_core.api.oauth_callback.callback"
        state = secrets.token_urlsafe(16)

        if registration_endpoint:
            print("  Registering OAuth client…", end="\r")
            reg = cls.register_client(registration_endpoint, callback_url)
            client_id = reg["client_id"]
            client_secret = reg.get("client_secret", "")
            print("  " + " " * 40, end="\r")
        else:
            raise RuntimeError(
                "Dynamic client registration is not enabled on this FAC site.\n"
                "  → Use API key auth instead: python bridge.py --add (choose option 2)"
            )

        # 4. Build authorization URL
        auth_params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": callback_url,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "all openid",
            "state": state,
        }
        approve_url = f"{auth_endpoint.replace('authorize', 'approve')}?{urlencode(auth_params)}"

        # 5. Show instructions
        print(f"\n  [bold]→ Step 1:[/] Log into your Frappe site:")
        print(f"    [cyan]{origin}[/]")
        print(f"\n  [bold]→ Step 2:[/] Open this URL in the [bold]same browser:[/]")
        print(f"    [cyan]{approve_url}[/]\n")
        print(f"  [dim]The page will confirm authorization — then you can close it.[/]")

        try:
            webbrowser.open(approve_url)
        except Exception:
            pass

        # 6. Poll for the authorization code
        print("  Waiting for authorization in browser…", end="\r")
        poll_url = f"{origin}/api/method/frappe_assistant_core.api.oauth_callback.get_code?state={state}"
        code: Optional[str] = None
        deadline = time.time() + OAUTH_TIMEOUT
        while time.time() < deadline:
            try:
                resp = requests.get(poll_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    # Frappe wraps responses in "message"
                    inner = data.get("message", data)
                    code = inner.get("code")
                    if code:
                        print("  " + " " * 50, end="\r")
                        break
                    if inner.get("error"):
                        raise RuntimeError(f"Authorization failed: {inner['error']}")
            except requests.RequestException:
                pass
            time.sleep(1)

        if not code:
            raise RuntimeError(
                "Authorization timed out.\n"
                "  → Make sure you opened the URL in a browser where you're logged into Frappe."
            )

        # 8. Exchange code for tokens
        print("  Exchanging code for tokens…", end="\r")
        basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        token_resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback_url,
                "code_verifier": code_verifier,
            },
            headers={"Authorization": f"Basic {basic_auth}"},
            timeout=15,
        )
        if token_resp.status_code != 200:
            raise RuntimeError(f"Token exchange failed ({token_resp.status_code}): {token_resp.text[:300]}")
        tokens = token_resp.json()
        print("  " + " " * 40, end="\r")

        # 9. Return credentials
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "expires_in": tokens.get("expires_in", 3600),
            "client_id": client_id,
            "client_secret": client_secret,
            "token_endpoint": token_endpoint,
        }


def _refresh_access_token(site_config: Dict[str, str]) -> Optional[str]:
    """Try to refresh an expired access token. Returns new access_token or None."""
    refresh_token = site_config.get("refresh_token")
    client_id = site_config.get("client_id")
    client_secret = site_config.get("client_secret")
    token_endpoint = site_config.get("token_endpoint")

    if not all([refresh_token, client_id, client_secret, token_endpoint]):
        return None

    try:
        basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        resp = requests.post(
            token_endpoint,
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers={"Authorization": f"Basic {basic_auth}"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            new_token = data.get("access_token")
            if new_token:
                site_config["access_token"] = new_token
                site_config["expires_in"] = data.get("expires_in", 3600)
                site_config["token_obtained_at"] = str(int(time.time()))
                if "refresh_token" in data:
                    site_config["refresh_token"] = data["refresh_token"]
                return new_token
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Site manager — saved FAC connectors (like Claude Desktop Connectors)
# ---------------------------------------------------------------------------
class SiteManager:
    """Manages saved FAC sites in ~/.fac_bridge/sites.json."""

    def __init__(self) -> None:
        self._path = CONFIG_FILE

    def _load(self) -> Dict[str, Any]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path) as f:
            return json.load(f)

    def _save(self, data: Dict[str, Any]) -> None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(self._path, 0o600)

    def list_sites(self) -> Dict[str, Dict[str, str]]:
        data = self._load()
        return data.get("sites", {})

    def add(self, name: str, site_data: Dict[str, Any]) -> None:
        data = self._load()
        data.setdefault("sites", {})[name] = site_data
        self._save(data)

    def remove(self, name: str) -> bool:
        data = self._load()
        if "sites" in data and name in data["sites"]:
            del data["sites"][name]
            self._save(data)
            return True
        return False

    def get(self, name: str) -> Optional[Dict[str, str]]:
        return self.list_sites().get(name)

    @staticmethod
    def suggest_name(url: str) -> str:
        hostname = urlparse(url).hostname or "site"
        return hostname.split(".")[0]


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------
def _pick_site(sites: Dict[str, Dict[str, str]]) -> Optional[str]:
    """Show a numbered menu of saved sites. Returns the chosen name or None."""
    names = list(sites.keys())
    if not names:
        return None

    if len(names) == 1:
        name = names[0]
        url = sites[name].get("url", "")
        print(f"\n  Only one site: [bold]{name}[/] ({urlparse(url).hostname})")
        if _confirm("  Connect?"):
            return name
        return None

    print(f"\n  [bold]FAC Sites:[/]")
    for i, name in enumerate(names, 1):
        url = sites[name].get("url", "")
        host = urlparse(url).hostname if "://" in url else url
        print(f"    {i}. [cyan]{name:<22}[/] ({host})")

    while True:
        choice = input(f"\n  Choose [1-{len(names)} or name]: ").strip()
        if choice in names:
            return choice
        try:
            idx = int(choice)
            if 1 <= idx <= len(names):
                return names[idx - 1]
        except ValueError:
            pass
        print(f"  [yellow]Invalid. Pick 1-{len(names)} or a site name.[/]")


def _add_site_interactive() -> Optional[str]:
    """Prompt for FAC URL, authenticate (OAuth or API key), save as a new site. Returns name or None."""
    print("\n  [bold]Add a new FAC site[/]")
    print("  ───────────────────")

    url = input("  FAC Endpoint URL: ").strip()
    if not url:
        print("  [red]✗[/] URL is required.")
        return None

    hostname = urlparse(url).hostname or "unknown"
    suggested = SiteManager.suggest_name(url)
    print(f"\n  [dim]✓ Detected: {hostname}[/]")

    name = input(f"  Short name [[cyan]{suggested}[/]]: ").strip()
    if not name:
        name = suggested

    mgr = SiteManager()
    existing = mgr.list_sites()
    if name in existing:
        print(f"  [yellow]⚠ Site \"{name}\" already exists.[/]")
        if not _confirm("  Overwrite?"):
            return None

    # Ask: OAuth (browser) or API Key?
    print()
    print("  [bold]Authentication method:[/]")
    print("    1. [cyan]OAuth (browser login)[/] — opens browser, log in, done")
    print("    2. [cyan]API Key + Secret[/] — paste credentials")

    choice = input("  Choose [1]: ").strip()
    use_api_key = choice == "2"

    if use_api_key:
        api_key = input("  API Key: ").strip()
        api_secret = input("  API Secret: ").strip()
        if not api_key or not api_secret:
            print("  [red]✗[/] API Key and Secret are required.")
            return None
        oauth_data = {}
    else:
        # OAuth flow
        try:
            oauth_data = OAuthFlow.authorize(url)
            print(f"\n  [green]✓[/] Authenticated via OAuth!")
        except Exception as e:
            print(f"\n  [red]✗ OAuth failed:[/] {e}")
            print("  [dim]Tip: Use API key auth instead — re-run --add and choose option 2.[/]")
            return None
        api_key = ""
        api_secret = ""

    site_data: Dict[str, Any] = {
        "url": url,
        "api_key": api_key,
        "api_secret": api_secret,
    }
    if oauth_data:
        site_data.update(oauth_data)

    mgr.add(name, site_data)
    msg = f"[green]✓[/] \"{name}\" saved. Connect with: [bold]python bridge.py {name}[/]"
    print(f"\n  {msg}")
    return name


def _confirm(prompt: str) -> bool:
    """Ask a yes/no question. Returns True for yes. Defaults to yes on EOF."""
    try:
        ans = input(f"{prompt} [Y/n]: ").strip().lower()
    except EOFError:
        ans = ""
    return ans in ("", "y", "yes")


# ---------------------------------------------------------------------------
# Terminal helpers (with / without Rich)
# ---------------------------------------------------------------------------
def _print(text: str = "", **kwargs: Any) -> None:
    """Print to console, Rich-aware."""
    if HAS_RICH and console is not None:
        console.print(text, **kwargs)
    else:
        # Strip Rich markup tags for plain-text fallback
        import re
        clean = re.sub(r"\[/?\w+\]", "", text)
        print(clean)


def _markdown(text: str) -> None:
    """Render markdown if Rich is available."""
    if HAS_RICH and console is not None:
        console.print(Markdown(text))
    else:
        print(text)


def _rule(title: str = "") -> None:
    if HAS_RICH and console is not None:
        console.rule(title)
    elif title:
        print(f"\n─── {title} ───")


def _ask(prompt: str) -> str:
    """Read user input with multi-line paste support like Claude Code."""
    _print(prompt)
    try:
        first_line = input("  ")
    except KeyboardInterrupt:
        raise
    except EOFError:
        return ""

    # Check if more lines were pasted (still in stdin buffer)
    import select as _select
    extra_lines = []
    while True:
        ready, _, _ = _select.select([sys.stdin], [], [], 0.05)
        if not ready:
            break
        line = sys.stdin.readline()
        if not line:
            break
        line = line.rstrip("\n")
        if line:
            extra_lines.append(line)

    if extra_lines:
        # Multi-line paste detected — show preview and confirm
        all_lines = [first_line] + extra_lines
        total = len(all_lines)
        _print(f"\n  [dim]Pasted {total} lines. Press Enter to confirm, or type to edit:[/]")
        preview = "\n".join(all_lines[:5])
        if total > 5:
            preview += f"\n  [dim]... and {total - 5} more lines[/]"
        _print(f"  [dim]───[/]")
        for line in all_lines[:5]:
            _print(f"  [dim]│[/] {line[:120]}")
        if total > 5:
            _print(f"  [dim]│ ... ({total - 5} more lines)[/]")
        _print(f"  [dim]───[/]")

        try:
            confirm = input("  ")
        except (EOFError, KeyboardInterrupt):
            return ""
        if confirm.strip():
            # User wants to edit — treat confirmation as the actual input
            return confirm
        return "\n".join(all_lines)

    return first_line


# ---------------------------------------------------------------------------
# MCP Client
# ---------------------------------------------------------------------------
class MCPClient:
    """Lightweight JSON-RPC 2.0 client for the Frappe MCP server.

    Supports two auth methods:
    - Bearer token (OAuth):  Authorization: Bearer <token>
    - API key/secret:        Authorization: token <key>:<secret>
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        api_secret: str = "",
        bearer_token: str = "",
        on_token_refresh: Any = None,  # callback to persist refreshed tokens
    ) -> None:
        # Sanitize: strip whitespace, newlines, and trailing slash
        self.url = url.strip().rstrip("/").replace("\n", "").replace("\r", "").replace(" ", "")
        self._request_id = 0
        self._bearer_token = bearer_token.strip() if bearer_token else ""
        self._on_token_refresh = on_token_refresh
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

        if self._bearer_token:
            self.session.headers["Authorization"] = f"Bearer {self._bearer_token}"
        else:
            api_key = api_key.strip().replace("\n", "").replace("\r", "").replace(" ", "")
            api_secret = api_secret.strip().replace("\n", "").replace("\r", "").replace(" ", "")
            self.session.headers["Authorization"] = f"token {api_key}:{api_secret}"

    # ------------------------------------------------------------------
    # Low-level RPC
    # ------------------------------------------------------------------
    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the result dict. Auto-refreshes Bearer tokens on 401."""
        return self._do_call(method, params, is_retry=False)

    def _do_call(self, method: str, params: Optional[Dict[str, Any]] = None, is_retry: bool = False) -> Dict[str, Any]:
        self._request_id += 1
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or {},
        }

        try:
            resp = self.session.post(self.url, json=payload, timeout=60)
        except requests.ConnectionError:
            raise ConnectionError(
                f"Cannot reach MCP server at {self.url}\n"
                "  → Check that the URL is correct and the Frappe server is running."
            )
        except requests.Timeout:
            raise ConnectionError(f"MCP server timed out at {self.url}")

        # Auto-refresh Bearer token on 401 (only once)
        if resp.status_code == 401 and self._bearer_token and not is_retry and self._on_token_refresh:
            new_token = self._on_token_refresh()
            if new_token:
                self._bearer_token = new_token
                self.session.headers["Authorization"] = f"Bearer {new_token}"
                return self._do_call(method, params, is_retry=True)

        if resp.status_code == 401:
            auth_msg = (
                "OAuth token expired and refresh failed. Re-add the site with: python bridge.py --add"
                if self._bearer_token
                else "Authentication failed (401). Check your API key and secret.\n"
                     "  → Generate them in Frappe: User → API Access → Generate Keys"
            )
            raise PermissionError(auth_msg)
        if resp.status_code == 403:
            raise PermissionError(
                "Access denied (403). Make sure 'Assistant Enabled' is checked on your User record."
            )

        resp.raise_for_status()

        try:
            data = resp.json()
        except json.JSONDecodeError:
            raise RuntimeError(f"MCP server returned non-JSON response:\n{resp.text[:500]}")

        if "error" in data:
            err = data["error"]
            raise RuntimeError(f"MCP Error [{err.get('code')}]: {err.get('message')}")

        return data.get("result", {})

    # ------------------------------------------------------------------
    # MCP protocol methods
    # ------------------------------------------------------------------
    def initialize(self) -> Dict[str, Any]:
        """Perform MCP initialize handshake."""
        return self._call(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "deepseek-frappe-bridge", "version": "1.0.0"},
            },
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """Retrieve the list of available tools from the MCP server."""
        result = self._call("tools/list")
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        """Execute a tool on the MCP server and return its text output."""
        result = self._call("tools/call", {"name": name, "arguments": arguments})

        content = result.get("content", [])
        # Extract text from content blocks (MCP spec)
        texts: List[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                texts.append(block["text"])

        return "\n".join(texts) if texts else json.dumps(result, default=str)


# ---------------------------------------------------------------------------
# Tool format conversion  (MCP → DeepSeek / OpenAI function format)
# ---------------------------------------------------------------------------
def mcp_tools_to_openai(mcp_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert MCP tool definitions to OpenAI/DeepSeek function-calling format."""
    converted: List[Dict[str, Any]] = []
    for tool in mcp_tools:
        schema = tool.get("inputSchema", {})
        # MCP uses "inputSchema"; OpenAI uses "parameters"
        params: Dict[str, Any] = {
            "type": schema.get("type", "object"),
            "properties": schema.get("properties", {}),
        }
        if "required" in schema:
            params["required"] = schema["required"]

        converted.append(
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": params,
                },
            }
        )
    return converted


# ---------------------------------------------------------------------------
# DeepSeek chat engine
# ---------------------------------------------------------------------------
class DeepSeekChat:
    """Wraps the OpenAI-compatible DeepSeek API with tool-calling support."""

    def __init__(self, api_key: str, model: str = DEEPSEEK_MODEL) -> None:
        self.client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
        self.model = model

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[str, Optional[List[Dict[str, Any]]]]:
        """
        Send messages to DeepSeek. Returns (text_content, tool_calls_or_None).

        When the model wants to call tools, text_content will be empty and
        tool_calls will contain the requested invocations.
        """
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 4096,
        }

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        try:
            response = self.client.chat.completions.create(**kwargs)  # type: ignore[arg-type]
        except Exception as exc:
            raise RuntimeError(f"DeepSeek API error: {exc}") from exc

        choice = response.choices[0]
        content = choice.message.content or ""
        tool_calls = choice.message.tool_calls

        if tool_calls:
            return content, [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in tool_calls
            ]

        return content, None


# ---------------------------------------------------------------------------
# Conversation manager
# ---------------------------------------------------------------------------
class Conversation:
    """Manages the message history for a chat session."""

    def __init__(self, system_prompt: Optional[str] = None) -> None:
        self.messages: List[Dict[str, Any]] = []
        if system_prompt:
            self.messages.append({"role": "system", "content": system_prompt})

    def add_user(self, content: str) -> None:
        self.messages.append({"role": "user", "content": content})

    def add_assistant(self, content: str, tool_calls: Optional[List[Dict[str, Any]]] = None) -> None:
        msg: Dict[str, Any] = {"role": "assistant", "content": content or None}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        self.messages.append(msg)

    def add_tool_result(self, tool_call_id: str, tool_name: str, content: str) -> None:
        self.messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": tool_name,
                "content": content,
            }
        )

    def get_messages(self) -> List[Dict[str, Any]]:
        return self.messages

    def trim(self, max_messages: int = 80) -> None:
        """Keep message history from growing too large. Never split tool exchanges."""
        if len(self.messages) <= max_messages:
            return
        # Always keep system message
        start = 1 if self.messages[0].get("role") == "system" else 0
        # Trim from the front, but only at user-message boundaries
        # This ensures tool_calls + tool results stay together
        keep = self.messages[-max_messages:]
        # Find the first user message in keep and cut from there
        for i, msg in enumerate(keep):
            if msg.get("role") == "user":
                self.messages = self.messages[:start] + keep[i:]
                return
        # Fallback: no user message found, keep as-is
        self.messages = self.messages[:start] + keep


# ---------------------------------------------------------------------------
# Bridge orchestrator
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Session persistence — save/restore conversation history
# ---------------------------------------------------------------------------
class SessionStore:
    """Persists conversation history to ~/.fac_bridge/sessions/<name>.json."""

    @staticmethod
    def _path(site_name: str) -> str:
        return os.path.join(SESSION_DIR, f"{site_name}.json")

    @staticmethod
    def save(site_name: str, messages: List[Dict[str, Any]]) -> None:
        os.makedirs(SESSION_DIR, exist_ok=True)
        data = {
            "site": site_name,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "message_count": len(messages),
            "messages": messages,
        }
        with open(SessionStore._path(site_name), "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load(site_name: str) -> Optional[List[Dict[str, Any]]]:
        path = SessionStore._path(site_name)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            return data.get("messages", [])
        except Exception:
            return None

    @staticmethod
    def delete(site_name: str) -> None:
        path = SessionStore._path(site_name)
        if os.path.exists(path):
            os.remove(path)

    @staticmethod
    def list_sessions() -> List[Dict[str, Any]]:
        result = []
        if not os.path.exists(SESSION_DIR):
            return result
        for f in sorted(os.listdir(SESSION_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(SESSION_DIR, f)) as fp:
                        data = json.load(fp)
                    result.append({
                        "name": f[:-5],
                        "updated": data.get("updated", "?"),
                        "messages": data.get("message_count", 0),
                    })
                except Exception:
                    pass
        return result


# ---------------------------------------------------------------------------
# Local machine tools — always available alongside FAC tools
# ---------------------------------------------------------------------------
class LocalTools:
    """Built-in tools that run on the local machine, not via MCP."""

    TOOLS: List[Dict[str, Any]] = [
        {
            "name": "run_shell_command",
            "description": "Run a shell command on the local machine. Use for file operations, git, "
            "grep, find, or any CLI tool. Commands run in the current working directory. "
            "30-second timeout. Avoid sudo or destructive commands.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to execute."},
                    "cwd": {"type": "string", "description": "Working directory. Defaults to current."},
                },
                "required": ["command"],
            },
        },
        {
            "name": "read_local_file",
            "description": "Read the contents of a file on the local filesystem.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the file to read."},
                    "max_lines": {"type": "integer", "default": 500, "description": "Max lines to return."},
                },
                "required": ["path"],
            },
        },
        {
            "name": "write_local_file",
            "description": "Write content to a file on the local filesystem. Only writes within "
            "the current working directory tree for safety.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to write to."},
                    "content": {"type": "string", "description": "Content to write."},
                },
                "required": ["path", "content"],
            },
        },
        {
            "name": "list_local_files",
            "description": "List files and directories in a local path.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path. Defaults to current directory."},
                    "pattern": {"type": "string", "description": "Optional glob pattern, e.g. '*.py'."},
                },
                "required": [],
            },
        },
        {
            "name": "list_bridge_sessions",
            "description": "List saved bridge conversation sessions AND current connection info (site name, URL). "
            "Use this when the user asks about sessions, saved conversations, bridge history, or which site/URL "
            "they are connected to.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    ]

    @staticmethod
    def execute(tool_name: str, arguments: Dict[str, Any]) -> str:
        """Execute a local tool. Returns result string."""
        if tool_name == "run_shell_command":
            return LocalTools._run_shell(arguments)
        elif tool_name == "read_local_file":
            return LocalTools._read_file(arguments)
        elif tool_name == "write_local_file":
            return LocalTools._write_file(arguments)
        elif tool_name == "list_local_files":
            return LocalTools._list_files(arguments)
        elif tool_name == "list_bridge_sessions":
            return LocalTools._list_sessions(arguments)
        return json.dumps({"error": f"Unknown local tool: {tool_name}"})

    @staticmethod
    def _run_shell(args: Dict[str, Any]) -> str:
        cmd = args.get("command", "")
        cwd = args.get("cwd") or os.getcwd()
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=30, cwd=cwd, env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
            out = result.stdout
            if result.stderr:
                out += "\n[stderr]\n" + result.stderr
            if result.returncode != 0:
                out += f"\n[exit code: {result.returncode}]"
            return out[:8000] if out else "(no output)"
        except subprocess.TimeoutExpired:
            return "Error: Command timed out (30s limit)."
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def _read_file(args: Dict[str, Any]) -> str:
        path = args.get("path", "")
        max_lines = args.get("max_lines", 500)
        try:
            p = Path(path).expanduser().resolve()
            content = p.read_text()
            lines = content.split("\n")
            if len(lines) > max_lines:
                lines = lines[:max_lines]
                lines.append(f"... (truncated, {len(content.split(chr(10)))} total lines)")
            return "\n".join(lines)
        except FileNotFoundError:
            return f"Error: File not found: {path}"
        except Exception as e:
            return f"Error reading file: {e}"

    @staticmethod
    def _write_file(args: Dict[str, Any]) -> str:
        path = args.get("path", "")
        content = args.get("content", "")
        try:
            p = Path(path).expanduser().resolve()
            # Safety: only write within CWD
            cwd = Path(os.getcwd()).resolve()
            if cwd not in p.parents and p != cwd and p.parent != cwd:
                return f"Error: Can only write within {cwd}. Requested: {p}"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            return f"Wrote {len(content)} bytes to {p}"
        except Exception as e:
            return f"Error writing file: {e}"

    @staticmethod
    def _list_sessions(args: Dict[str, Any]) -> str:
        sessions = SessionStore.list_sessions()
        if not sessions:
            return "No saved sessions."
        lines = [f"{len(sessions)} saved session(s):"]
        for s in sessions:
            lines.append(f"  {s['name']}: {s['messages']} messages, last updated {s['updated']}")
        return "\n".join(lines)

    @staticmethod
    def _list_files(args: Dict[str, Any]) -> str:
        path = args.get("path") or os.getcwd()
        pattern = args.get("pattern") or "*"
        try:
            p = Path(path).expanduser().resolve()
            matches = list(p.glob(pattern))[:200]
            lines = []
            for m in sorted(matches, key=lambda x: (not x.is_dir(), x.name.lower())):
                suffix = "/" if m.is_dir() else ""
                size = ""
                if m.is_file():
                    try:
                        size = f" ({m.stat().st_size:,} bytes)"
                    except Exception:
                        pass
                lines.append(f"  {m.relative_to(p)}{suffix}{size}")
            return f"{len(matches)} items in {p}:\n" + "\n".join(lines)
        except Exception as e:
            return f"Error listing files: {e}"


def _local_tools_as_openai() -> List[Dict[str, Any]]:
    """Convert local tools to OpenAI/DeepSeek function format."""
    result = []
    for t in LocalTools.TOOLS:
        schema = t.get("inputSchema", {})
        params = {"type": schema.get("type", "object"), "properties": schema.get("properties", {})}
        if "required" in schema:
            params["required"] = schema["required"]
        result.append({
            "type": "function",
            "function": {"name": t["name"], "description": t["description"], "parameters": params},
        })
    return result


class DeepSeekFrappeBridge:
    """Orchestrates the DeepSeek ↔ Frappe MCP bridge conversation loop."""

    def __init__(
        self,
        mcp_url: str,
        api_key: str = "",
        api_secret: str = "",
        deepseek_api_key: str = "",
        bearer_token: str = "",
        model: str = DEEPSEEK_MODEL,
        verbose: bool = False,
        on_token_refresh: Any = None,
        site_name: str = "",
        fresh: bool = False,
    ) -> None:
        self.verbose = verbose
        self.mcp_url = mcp_url
        self.site_name = site_name
        self.fresh = fresh
        self.mcp = MCPClient(
            url=mcp_url,
            api_key=api_key,
            api_secret=api_secret,
            bearer_token=bearer_token,
            on_token_refresh=on_token_refresh,
        )
        self.chat = DeepSeekChat(deepseek_api_key, model)
        self.conversation: Optional[Conversation] = None
        self.tools_openai: List[Dict[str, Any]] = []
        self.tool_names: List[str] = []
        self._message_queue: List[str] = []
        self._queue_lock = threading.Lock()
        self._processing = False

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def connect(self) -> List[Dict[str, Any]]:
        """Initialize MCP session and discover tools. Returns tool list."""
        # 1. Initialize MCP session
        init_result = self.mcp.initialize()
        server_name = init_result.get("serverInfo", {}).get("name", "unknown")
        protocol = init_result.get("protocolVersion", "unknown")
        _print(f"[green]✓[/] Connected to [bold]{server_name}[/] (MCP {protocol})")

        # 2. Discover tools
        mcp_tools = self.mcp.list_tools()
        # Merge local tools with remote FAC tools
        local_openai = _local_tools_as_openai()
        remote_openai = mcp_tools_to_openai(mcp_tools)
        self.tools_openai = local_openai + remote_openai
        self.tool_names = [t["name"] for t in LocalTools.TOOLS] + [t["name"] for t in mcp_tools]

        _print(f"[green]✓[/] Discovered [bold]{len(mcp_tools)}[/] remote + [bold]{len(LocalTools.TOOLS)}[/] local tools")
        if self.verbose:
            for t in LocalTools.TOOLS:
                _print(f"  • [cyan]{t['name']}[/] [dim](local)[/] — {t.get('description', '')[:60]}")
            for t in mcp_tools:
                _print(f"  • [cyan]{t['name']}[/] — {t.get('description', '')[:80]}")

        return mcp_tools

    # ------------------------------------------------------------------
    # Single exchange
    # ------------------------------------------------------------------
    def process_message(self, user_input: str) -> str:
        """Send user message and resolve any tool calls. Returns final response text."""
        self.conversation.add_user(user_input)

        last_tool: str = ""
        same_tool_count: int = 0

        for _round in range(MAX_TOOL_ROUNDS):
            self.conversation.trim()
            messages = self.conversation.get_messages()

            # Send to DeepSeek
            text, tool_calls = self.chat.chat(messages, tools=self.tools_openai)

            # No tool calls → this is the final answer
            if not tool_calls:
                return text or "(no response)"

            # Model wants to call tools — execute them
            self.conversation.add_assistant(text, tool_calls)

            # Detect infinite loops: same tool 3+ consecutive times
            tool_names_list = [tc["function"]["name"] for tc in tool_calls]
            if tool_names_list and all(n == tool_names_list[0] for n in tool_names_list):
                if tool_names_list[0] == last_tool:
                    same_tool_count += 1
                    if same_tool_count >= 3:
                        # Don't add the tool_calls message — just return the break message
                        return (
                            f"I called {tool_names_list[0]} {same_tool_count} times without progress. "
                            "Let me try a different approach or ask the user for guidance."
                        )
                else:
                    last_tool = tool_names_list[0]
                    same_tool_count = 1

            self.conversation.add_assistant(text, tool_calls)

            for tc in tool_calls:
                fn_name = tc["function"]["name"]
                try:
                    fn_args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    fn_args = {}

                _print(f"  [dim]🔧 Calling [cyan]{fn_name}[/]…[/]")

                try:
                    # Route to local or remote tool
                    local_names = [t["name"] for t in LocalTools.TOOLS]
                    if fn_name in local_names:
                        result_text = LocalTools.execute(fn_name, fn_args)
                    else:
                        result_text = self.mcp.call_tool(fn_name, fn_args)
                except Exception as exc:
                    result_text = f"Error: {exc}"

                # Truncate very large results (but keep enough context)
                if len(result_text) > 8000:
                    result_text = result_text[:8000] + "\n… [truncated]"

                self.conversation.add_tool_result(tc["id"], fn_name, result_text)

        return "⚠️ Reached maximum tool-calling rounds — the task may be too complex."

    # ------------------------------------------------------------------
    # Interactive loop
    # ------------------------------------------------------------------
    def run(self) -> None:
        """Main interactive chat loop."""
        # Connect and discover tools
        try:
            mcp_tools = self.connect()
        except (ConnectionError, PermissionError, RuntimeError) as exc:
            _print(f"\n[red]✗ Connection failed:[/] {exc}")
            sys.exit(1)

        if not mcp_tools:
            _print("\n[yellow]⚠ No tools discovered. The assistant can chat but cannot access ERPNext data.[/]")

        # Try to resume previous session
        if not self.fresh and self.site_name:
            saved = SessionStore.load(self.site_name)
            if saved:
                self.conversation = Conversation()
                self.conversation.messages = saved
                _print(f"[dim]↻ Resumed session ({len(saved)} messages)[/]")
            else:
                self.conversation = Conversation(self._build_system_prompt(mcp_tools))
        else:
            self.conversation = Conversation(self._build_system_prompt(mcp_tools))

        # Welcome
        _rule("DeepSeek + Frappe Assistant Core")
        _markdown(
            f"Connected to [bold]{self.mcp.url}[/] with [bold]{len(mcp_tools)} remote + {len(LocalTools.TOOLS)} local tools[/].\n"
            f"Model: [bold]{self.chat.model}[/]\n"
            "Type [bold]/help[/] for commands, [bold]/exit[/] to quit."
        )
        _rule()

        def _auto_save():
            """Save session after each exchange."""
            if self.site_name and self.conversation:
                SessionStore.save(self.site_name, self.conversation.messages)

        # Chat loop
        while True:
            # Show queue status if items are pending
            with self._queue_lock:
                pending = len(self._message_queue)
            if pending:
                _print(f"\n[dim]({pending} queued)[/]")

            try:
                user_input = _ask("\n[bold blue]▸ You[/]")
            except (EOFError, KeyboardInterrupt):
                _print("\n[dim]Goodbye![/]")
                break

            user_input = user_input.strip()
            if not user_input:
                continue

            # Handle commands
            if user_input.startswith("/"):
                self._handle_command(user_input)
                continue
            if user_input.lower() in ("exit", "quit"):
                _print("[dim]Goodbye![/] (use /exit next time)")
                sys.exit(0)

            # Queue mode: `! message` — queue and continue accepting input
            if user_input.startswith("!"):
                queued_msg = user_input[1:].strip()
                if not queued_msg:
                    continue
                with self._queue_lock:
                    self._message_queue.append(queued_msg)
                _print(f"  [dim]Queued ({len(self._message_queue)} pending)[/]")
                if not self._processing:
                    self._processing = True
                    threading.Thread(target=self._process_queue, daemon=True).start()
                continue

            # Process message inline
            self._process_one(user_input)

    # ------------------------------------------------------------------
    # Queue processing
    # ------------------------------------------------------------------
    def _process_queue(self) -> None:
        """Process queued messages in background thread."""
        while True:
            with self._queue_lock:
                if not self._message_queue:
                    self._processing = False
                    return
                msg = self._message_queue.pop(0)
            self._process_one(msg)

    def _process_one(self, user_input: str) -> None:
        """Process a single message and display the response."""
        try:
            if HAS_RICH and console is not None:
                with console.status("[dim]Thinking… (Ctrl+C to cancel)[/]", spinner="dots"):
                    response = self.process_message(user_input)
            else:
                print("Thinking… (Ctrl+C to cancel)", end="\r")
                response = self.process_message(user_input)
                print(" " * 30, end="\r")
        except KeyboardInterrupt:
            _print("\n  [dim]Cancelled.[/]")
            if self.site_name and self.conversation:
                SessionStore.save(self.site_name, self.conversation.messages)
            return
        except RuntimeError as exc:
            _print(f"\n[red]✗ Error:[/] {exc}")
            return
        except Exception as exc:
            _print(f"\n[red]✗ Unexpected error:[/] {exc}")
            return

        # Display response and auto-save
        _print()
        _markdown(response)
        if self.site_name and self.conversation:
            SessionStore.save(self.site_name, self.conversation.messages)

    def _build_system_prompt(self, mcp_tools: list) -> str:
        site_info = ""
        if self.site_name:
            site_info = f"You are connected to FAC site \"{self.site_name}\" at {self.mcp_url}.\n"
        return textwrap.dedent(f"""\
            You are a helpful ERPNext assistant powered by DeepSeek.
            {site_info}You have access to {len(LocalTools.TOOLS)} local tools and {len(mcp_tools)} ERPNext tools.

            Remote tools: {', '.join([t['name'] for t in mcp_tools][:20])}
            Local tools: {', '.join([t['name'] for t in LocalTools.TOOLS])}

            Guidelines:
            - Use tools to look up, create, or update information in ERPNext.
            - Use local tools for file operations and shell commands.
            - Be specific with doctype names (e.g., "Customer", "Sales Invoice").
            - Always confirm when creating or modifying records.
            - Format responses clearly using markdown.
        """)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------
    def _handle_command(self, cmd: str) -> None:
        """Handle slash commands."""
        cmd = cmd.lower().strip()

        if cmd in ("/exit", "/quit"):
            _print("[dim]Goodbye![/]")
            sys.exit(0)

        elif cmd == "/help":
            _markdown(
                textwrap.dedent("""\
                **Available Commands:**
                - `! message` — queue a message for background processing
                - `/tools` — list all available tools (local + remote)
                - `/queue` — show queued messages
                - `/cancel` — clear the message queue
                - `/clear` — clear conversation history
                - `/save` — explicitly save current session
                - `/reset` — clear history + delete saved session
                - `/sessions` — list saved sessions
                - `/history` — show conversation message count
                - `/help`  — show this help
                - `/exit`  — quit the bridge
            """)
            )

        elif cmd == "/tools":
            if not self.tool_names:
                _print("[dim]No tools available.[/]")
                return
            local_names = [t["name"] for t in LocalTools.TOOLS]
            _print(f"\n[bold]Available Tools ({len(self.tool_names)}):[/]")
            for name in self.tool_names:
                tag = " [dim](local)[/]" if name in local_names else ""
                _print(f"  • [cyan]{name}[/]{tag}")

        elif cmd == "/queue":
            with self._queue_lock:
                pending = list(self._message_queue)
            if not pending:
                _print("[dim]No queued messages.[/]")
            else:
                _print(f"[bold]{len(pending)} queued:[/]")
                for i, msg in enumerate(pending, 1):
                    _print(f"  {i}. [dim]{msg[:80]}[/]")

        elif cmd == "/cancel":
            with self._queue_lock:
                count = len(self._message_queue)
                self._message_queue.clear()
            _print(f"[green]✓[/] Cleared {count} queued message(s).")

        elif cmd == "/clear":
            if self.conversation:
                sys_msg = self.conversation.messages[0] if self.conversation.messages else None
                self.conversation = Conversation(
                    system_prompt=sys_msg["content"] if sys_msg and sys_msg.get("role") == "system" else None
                )
            _print("[green]✓[/] Conversation history cleared.")

        elif cmd == "/save":
            if self.site_name and self.conversation:
                SessionStore.save(self.site_name, self.conversation.messages)
                count = len(self.conversation.messages)
                _print(f"[green]✓[/] Session saved ({count} messages)")
            else:
                _print("[dim]No session to save.[/]")

        elif cmd == "/reset":
            if self.conversation:
                sys_msg = self.conversation.messages[0] if self.conversation.messages else None
                self.conversation = Conversation(
                    system_prompt=sys_msg["content"] if sys_msg and sys_msg.get("role") == "system" else None
                )
            if self.site_name:
                SessionStore.delete(self.site_name)
            _print("[green]✓[/] Session reset — history cleared and saved session deleted.")

        elif cmd == "/sessions":
            sessions = SessionStore.list_sessions()
            if not sessions:
                _print("[dim]No saved sessions.[/]")
            else:
                _print(f"\n[bold]Saved Sessions ({len(sessions)}):[/]")
                for s in sessions:
                    _print(f"  [cyan]{s['name']:<20}[/] {s['messages']} msgs — {s['updated']}")

        elif cmd == "/history":
            count = len(self.conversation.messages) if self.conversation else 0
            _print(f"[dim]Messages in history: {count}[/]")

        else:
            _print(f"[yellow]Unknown command:[/] {cmd} — type /help for available commands.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="DeepSeek ↔ Frappe Assistant Core Bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Connect to a saved site
              python bridge.py v15upgrade

              # Pick from saved sites interactively
              python bridge.py

              # Manage sites
              python bridge.py --add
              python bridge.py --list
              python bridge.py --remove

              # Direct connection (env vars or CLI flags)
              export FRAUD_ASSISTANT_MCP_URL="https://..."
              export FRAUD_ASSISTANT_API_KEY="..."
              export FRAUD_ASSISTANT_API_SECRET="..."
              python bridge.py
        """),
    )

    # Positional: site name
    parser.add_argument(
        "site",
        nargs="?",
        default=None,
        help="Name of a saved FAC site to connect to",
    )

    # Site management
    parser.add_argument("--add", action="store_true", help="Add a new FAC site interactively")
    parser.add_argument("--list", action="store_true", help="List saved FAC sites")
    parser.add_argument("--remove", action="store_true", help="Remove a saved FAC site")

    # Direct connection settings (overrides)
    parser.add_argument(
        "--mcp-url",
        default=os.environ.get("FRAUD_ASSISTANT_MCP_URL", ""),
        help="MCP endpoint URL (env: FRAUD_ASSISTANT_MCP_URL)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("FRAUD_ASSISTANT_API_KEY", ""),
        help="Frappe API key (env: FRAUD_ASSISTANT_API_KEY)",
    )
    parser.add_argument(
        "--api-secret",
        default=os.environ.get("FRAUD_ASSISTANT_API_SECRET", ""),
        help="Frappe API secret (env: FRAUD_ASSISTANT_API_SECRET)",
    )
    parser.add_argument(
        "--deepseek-api-key",
        default=os.environ.get("DEEPSEEK_API_KEY", ""),
        help="DeepSeek API key (env: DEEPSEEK_API_KEY)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("DEEPSEEK_MODEL", DEEPSEEK_MODEL),
        help=f"DeepSeek model to use (default: {DEEPSEEK_MODEL})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed tool discovery and debug info",
    )
    parser.add_argument(
        "--fresh", action="store_true", help="Start fresh (ignore saved session)"
    )

    args = parser.parse_args(argv)
    mgr = SiteManager()

    # --- Site management commands (short-circuit) ---
    if args.list:
        sites = mgr.list_sites()
        if not sites:
            print("No FAC sites saved.")
            print("Add one with: python bridge.py --add")
        else:
            print(f"\n[bold]Saved FAC sites ({len(sites)}):[/]")
            for name, cfg in sites.items():
                host = urlparse(cfg["url"]).hostname or cfg["url"]
                print(f"  [cyan]{name:<22}[/] {host}")
        return

    if args.remove:
        sites = mgr.list_sites()
        if not sites:
            print("No FAC sites to remove.")
            return
        name = _pick_site(sites)
        if name and _confirm(f"Remove \"{name}\"?"):
            mgr.remove(name)
            print(f"[green]✓[/] \"{name}\" removed.")
        return

    if args.add:
        name = _add_site_interactive()
        if name:
            if _confirm("\n  Connect now?"):
                site = mgr.get(name)
                assert site is not None
                site_name_for_refresh = name
            else:
                return
        else:
            return
    else:
        # --- Resolve connection config ---
        # Priority: CLI flags > env vars > positional site > interactive picker
        mcp_url = args.mcp_url
        api_key = args.api_key
        api_secret = args.api_secret

        if mcp_url and api_key and api_secret:
            # Full config from env vars or CLI flags — use directly
            site = None
            site_name_for_refresh = ""
        elif args.site:
            site = mgr.get(args.site)
            if not site:
                print(f"[red]✗[/] Site \"{args.site}\" not found.")
                sites = mgr.list_sites()
                if sites:
                    print(f"  Available: {', '.join(sites.keys())}")
                print("  Add it with: python bridge.py --add")
                sys.exit(1)
            site_name_for_refresh = args.site
        elif not mcp_url:
            sites = mgr.list_sites()
            if not sites:
                print("\n  [bold]No FAC sites configured.[/]")
                print("  Paste your FAC Endpoint URL to get started.\n")
                name = _add_site_interactive()
                if not name:
                    sys.exit(0)
                site = mgr.get(name)
                assert site is not None
                site_name_for_refresh = name
            else:
                name = _pick_site(sites)
                if not name:
                    print("  [dim]Cancelled.[/]")
                    sys.exit(0)
                site = mgr.get(name)
                assert site is not None
                site_name_for_refresh = name

    # --- Extract credentials from site config ---
    if site:
        mcp_url = site["url"]
        api_key = site.get("api_key", "")
        api_secret = site.get("api_secret", "")
        bearer_token = site.get("access_token", "")
    else:
        bearer_token = ""

    # --- Token refresh callback (persists refreshed tokens to sites.json) ---
    def _persist_refreshed_token(new_token: str) -> bool:
        if not site_name_for_refresh or not site:
            return False
        mgr2 = SiteManager()
        site_data = mgr2.get(site_name_for_refresh)
        if site_data:
            site_data["access_token"] = new_token
            site_data["token_obtained_at"] = str(int(time.time()))
            mgr2.add(site_name_for_refresh, site_data)
        return True

    # Check if OAuth token might need refresh (older than 80% of expiry)
    if bearer_token and site:
        expires_in = int(site.get("expires_in", 3600))
        obtained = int(site.get("token_obtained_at", "0"))
        if obtained and time.time() - obtained > expires_in * 0.8:
            new_token = _refresh_access_token(site)
            if new_token:
                bearer_token = new_token
                _persist_refreshed_token(new_token)

    on_token_refresh = (lambda t: _refresh_access_token(site) if site else None) if site and bearer_token else None

    # --- Validate DeepSeek key ---
    deepseek_api_key = args.deepseek_api_key
    if not deepseek_api_key:
        print("[red]✗[/] DeepSeek API key is required.")
        print("  Set it via DEEPSEEK_API_KEY env variable or --deepseek-api-key flag.")
        print("  Get a key at: https://platform.deepseek.com")
        sys.exit(1)

    # --- Launch ---
    bridge = DeepSeekFrappeBridge(
        mcp_url=mcp_url,
        api_key=api_key,
        api_secret=api_secret,
        deepseek_api_key=deepseek_api_key,
        bearer_token=bearer_token,
        model=args.model,
        verbose=args.verbose,
        on_token_refresh=on_token_refresh,
        site_name=site_name_for_refresh,
        fresh=args.fresh,
    )
    bridge.run()


if __name__ == "__main__":
    main()
