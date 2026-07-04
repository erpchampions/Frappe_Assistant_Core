#!/usr/bin/env python3
"""
FAC Bridge — MCP proxy server for Frappe Assistant Core sites.

Exposes tools from one or more FAC sites as a local MCP server that
Claude Code (or any MCP client) can connect to.

Usage:
    python bridge.py serve                 # serve all saved sites
    python bridge.py serve v15upgrade      # serve specific sites
    python bridge.py --add                 # add a new site
    python bridge.py --list                # list saved sites
    python bridge.py --remove              # remove a site
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import sys
import textwrap
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

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
    console = None
    HAS_RICH = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".fac_bridge")
CONFIG_FILE = os.path.join(CONFIG_DIR, "sites.json")
DEFAULT_PORT = 9090
MCP_PROTOCOL_VERSION = "2025-06-18"

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------
def _print(text: str = "", **kwargs: Any) -> None:
    if HAS_RICH and console is not None:
        console.print(text, **kwargs)
    else:
        import re
        clean = re.sub(r"\[/?\w+\]", "", text)
        print(clean)

def _rule(title: str = "") -> None:
    if HAS_RICH and console is not None:
        console.rule(title)
    elif title:
        print(f"\n─── {title} ───")

def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [Y/n]: ").strip().lower()
    except EOFError:
        ans = ""
    return ans in ("", "y", "yes")

# ---------------------------------------------------------------------------
# OAuth 2.0 flow
# ---------------------------------------------------------------------------
class OAuthFlow:
    """Handles OAuth 2.0 authorization code flow with PKCE for FAC sites."""

    @staticmethod
    def discover(base_url: str) -> Dict[str, str]:
        base = base_url.rstrip("/")
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        resp = requests.get(f"{origin}/.well-known/openid-configuration", timeout=15)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def generate_pkce() -> Tuple[str, str]:
        verifier = secrets.token_urlsafe(64)[:128]
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return verifier, challenge

    @staticmethod
    def register_client(registration_url: str, redirect_uri: str) -> Dict[str, str]:
        payload = {
            "client_name": "FAC Bridge",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "all openid",
        }
        resp = requests.post(registration_url, json=payload, timeout=15)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"OAuth client registration failed ({resp.status_code}): {resp.text[:300]}")
        return resp.json()

    @classmethod
    def authorize(cls, fac_url: str) -> Dict[str, Any]:
        """Full OAuth authorization flow using FAC callback endpoint."""
        base = fac_url.rstrip("/")
        origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"

        print("  Discovering OAuth endpoints…", end="\r")
        metadata = cls.discover(base)
        auth_endpoint = metadata["authorization_endpoint"]
        token_endpoint = metadata["token_endpoint"]
        registration_endpoint = metadata.get("registration_endpoint")
        print("  " + " " * 40, end="\r")

        code_verifier, code_challenge = cls.generate_pkce()
        callback_url = f"{origin}/api/method/frappe_assistant_core.api.oauth_callback.callback"
        state = secrets.token_urlsafe(16)

        if not registration_endpoint:
            raise RuntimeError("Dynamic client registration is not enabled on this FAC site. Use API key auth (option 2).")
        print("  Registering OAuth client…", end="\r")
        reg = cls.register_client(registration_endpoint, callback_url)
        client_id = reg["client_id"]
        client_secret = reg.get("client_secret", "")
        print("  " + " " * 40, end="\r")

        auth_params = {
            "client_id": client_id, "response_type": "code", "redirect_uri": callback_url,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
            "scope": "all openid", "state": state,
        }
        approve_url = f"{auth_endpoint.replace('authorize', 'approve')}?{urlencode(auth_params)}"

        print(f"\n  → Step 1: Log into your Frappe site: [cyan]{origin}[/]")
        print(f"  → Step 2: Open this URL in the same browser:")
        print(f"    [cyan]{approve_url}[/]")
        print(f"  → The page will confirm authorization — close it and the bridge auto-detects.")

        try:
            webbrowser.open(approve_url)
        except Exception:
            pass

        print("  Waiting for authorization…", end="\r")
        poll_url = f"{origin}/api/method/frappe_assistant_core.api.oauth_callback.get_code?state={state}"
        code = None
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                resp = requests.get(poll_url, timeout=5)
                if resp.status_code == 200:
                    inner = resp.json().get("message", {})
                    code = inner.get("code")
                    if code:
                        break
            except requests.RequestException:
                pass
            time.sleep(1)

        if not code:
            raise RuntimeError("Authorization timed out.")

        print("  Exchanging code for tokens…", end="\r")
        basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        token_resp = requests.post(
            token_endpoint,
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": callback_url,
                  "code_verifier": code_verifier},
            headers={"Authorization": f"Basic {basic_auth}"}, timeout=15,
        )
        if token_resp.status_code != 200:
            raise RuntimeError(f"Token exchange failed: {token_resp.text[:300]}")
        tokens = token_resp.json()
        print("  " + " " * 40, end="\r")

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
            headers={"Authorization": f"Basic {basic_auth}"}, timeout=15,
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
# Site manager
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
        return self._load().get("sites", {})

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
# Interactive site management
# ---------------------------------------------------------------------------
def _pick_site(sites: Dict[str, Dict[str, str]]) -> Optional[str]:
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
        print(f"  Invalid. Pick 1-{len(names)} or a site name.")


def _add_site_interactive() -> Optional[str]:
    print("\n  [bold]Add a new FAC site[/]")
    print("  ───────────────────")
    url = input("  FAC Endpoint URL: ").strip()
    if not url:
        print("  ✗ URL is required.")
        return None
    hostname = urlparse(url).hostname or "unknown"
    suggested = SiteManager.suggest_name(url)
    print(f"\n  ✓ Detected: {hostname}")
    name = input(f"  Short name [[cyan]{suggested}[/]]: ").strip()
    if not name:
        name = suggested
    mgr = SiteManager()
    existing = mgr.list_sites()
    if name in existing:
        print(f"  ⚠ Site \"{name}\" already exists.")
        if not _confirm("  Overwrite?"):
            return None

    print(f"\n  [bold]Authentication method:[/]")
    print("    1. OAuth (browser login) — opens browser, log in, done")
    print("    2. API Key + Secret — paste credentials")
    choice = input("  Choose [1]: ").strip()
    use_api_key = choice == "2"

    if use_api_key:
        api_key = input("  API Key: ").strip()
        api_secret = input("  API Secret: ").strip()
        if not api_key or not api_secret:
            print("  ✗ API Key and Secret are required.")
            return None
        oauth_data = {}
    else:
        try:
            oauth_data = OAuthFlow.authorize(url)
            print(f"\n  ✓ Authenticated via OAuth!")
        except Exception as e:
            print(f"\n  ✗ OAuth failed: {e}")
            print("  Tip: Use API key auth instead — re-run --add and choose option 2.")
            return None
        api_key = ""
        api_secret = ""

    site_data: Dict[str, Any] = {"url": url, "api_key": api_key, "api_secret": api_secret}
    if oauth_data:
        site_data.update(oauth_data)

    mgr.add(name, site_data)
    print(f"\n  ✓ \"{name}\" saved.")
    return name


# ---------------------------------------------------------------------------
# MCP Client — talks MCP to a single FAC site
# ---------------------------------------------------------------------------
class MCPClient:
    """Lightweight JSON-RPC 2.0 client for a FAC MCP server."""

    def __init__(self, url: str, api_key: str = "", api_secret: str = "",
                 bearer_token: str = "", on_token_refresh: Any = None) -> None:
        self.url = url.strip().rstrip("/").replace("\n", "").replace("\r", "").replace(" ", "")
        self._request_id = 0
        self._bearer_token = bearer_token.strip() if bearer_token else ""
        self._on_token_refresh = on_token_refresh
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
        if self._bearer_token:
            self.session.headers["Authorization"] = f"Bearer {self._bearer_token}"
        else:
            api_key = api_key.strip().replace("\n", "").replace("\r", "").replace(" ", "")
            api_secret = api_secret.strip().replace("\n", "").replace("\r", "").replace(" ", "")
            self.session.headers["Authorization"] = f"token {api_key}:{api_secret}"

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._do_call(method, params, is_retry=False)

    def _do_call(self, method: str, params: Optional[Dict[str, Any]] = None,
                 is_retry: bool = False) -> Dict[str, Any]:
        self._request_id += 1
        payload = {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params or {}}
        try:
            resp = self.session.post(self.url, json=payload, timeout=60)
        except requests.ConnectionError:
            raise ConnectionError(f"Cannot reach MCP server at {self.url}")
        except requests.Timeout:
            raise ConnectionError(f"MCP server timed out at {self.url}")

        if resp.status_code == 401 and self._bearer_token and not is_retry and self._on_token_refresh:
            new_token = self._on_token_refresh()
            if new_token:
                self._bearer_token = new_token
                self.session.headers["Authorization"] = f"Bearer {new_token}"
                return self._do_call(method, params, is_retry=True)

        if resp.status_code == 401:
            auth_msg = "OAuth token expired and refresh failed. Re-add the site with: python bridge.py --add"
            raise PermissionError(auth_msg)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"MCP Error [{data['error'].get('code')}]: {data['error'].get('message')}")
        return data.get("result", {})

    def initialize(self) -> Dict[str, Any]:
        return self._call("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "fac-bridge", "version": "2.0.0"},
        })

    def list_tools(self) -> List[Dict[str, Any]]:
        return self._call("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        result = self._call("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content", [])
        texts = [block["text"] for block in content if isinstance(block, dict) and block.get("type") == "text"]
        return "\n".join(texts) if texts else json.dumps(result, default=str)


# ---------------------------------------------------------------------------
# MCP Server Bridge — proxies FAC sites to a local MCP server
# ---------------------------------------------------------------------------
class MCPServerBridge:
    """Runs a local MCP HTTP server that proxies tools from FAC sites."""

    def __init__(self, port: int = DEFAULT_PORT, sites: Optional[List[str]] = None) -> None:
        self.port = port
        self.site_names: List[str] = sites or []
        self.clients: Dict[str, MCPClient] = {}
        self.tools: Dict[str, Dict[str, Any]] = {}  # prefixed_name -> {site, original_name, schema}
        self._lock = threading.Lock()

    def start(self) -> None:
        """Connect to all sites, discover tools, start HTTP server."""
        mgr = SiteManager()
        all_sites = mgr.list_sites()

        if not self.site_names:
            self.site_names = list(all_sites.keys())
        if not self.site_names:
            print("No FAC sites configured. Add one with: python bridge.py --add")
            sys.exit(1)

        # Connect to each site and discover tools
        for name in self.site_names:
            cfg = all_sites.get(name)
            if not cfg:
                print(f"  ✗ Site '{name}' not found. Skipping.")
                continue
            try:
                client = self._make_client(name, cfg)
                client.initialize()
                tools = client.list_tools()
                self.clients[name] = client
                # Register tools with site prefix
                for tool in tools:
                    prefixed = f"{name}__{tool['name']}"
                    self.tools[prefixed] = {"site": name, "original_name": tool["name"],
                                             "description": tool.get("description", ""),
                                             "inputSchema": tool.get("inputSchema", {})}
                print(f"  ✓ {name}: {len(tools)} tools")
            except Exception as e:
                print(f"  ✗ {name}: {e}")

        if not self.clients:
            print("No sites connected. Check your credentials.")
            sys.exit(1)

        print(f"\n  Bridge running on [bold]http://localhost:{self.port}[/]")
        print(f"  {len(self.tools)} tools from {len(self.clients)} site(s)")
        print(f"  Add to Claude Code as an MCP connector.\n")

        # Start HTTP server
        handler = self._make_handler()
        server = HTTPServer(("127.0.0.1", self.port), handler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Shutting down…")
            server.server_close()

    def _make_client(self, name: str, cfg: Dict[str, str]) -> MCPClient:
        """Create MCPClient for a site, with OAuth token handling."""
        access_token = cfg.get("access_token", "")
        if access_token:
            # Check if token might need refresh
            expires_in = int(cfg.get("expires_in", 3600))
            obtained = int(cfg.get("token_obtained_at", "0"))
            if obtained and time.time() - obtained > expires_in * 0.8:
                new_token = _refresh_access_token(cfg)
                if new_token:
                    access_token = new_token
                    # Persist refreshed token
                    mgr = SiteManager()
                    mgr.add(name, cfg)

            def make_refresh_callback(site_cfg, site_name):
                def refresh():
                    new_tok = _refresh_access_token(site_cfg)
                    if new_tok:
                        mgr2 = SiteManager()
                        mgr2.add(site_name, site_cfg)
                    return new_tok
                return refresh

            return MCPClient(cfg["url"], bearer_token=access_token,
                             on_token_refresh=make_refresh_callback(cfg, name))
        else:
            return MCPClient(cfg["url"], api_key=cfg.get("api_key", ""),
                             api_secret=cfg.get("api_secret", ""))

    def _make_handler(self) -> type:
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                    data = json.loads(body)
                except Exception:
                    self._respond(400, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700, "message": "Parse error"}})
                    return

                req_id = data.get("id")
                method = data.get("method", "")
                params = data.get("params", {})

                try:
                    if method == "initialize":
                        result = {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "fac-bridge", "version": "2.0.0"},
                        }
                    elif method == "tools/list":
                        tools_list = []
                        for prefixed, info in bridge.tools.items():
                            tools_list.append({
                                "name": prefixed,
                                "description": f"[{info['site']}] {info['description']}",
                                "inputSchema": info["inputSchema"],
                            })
                        result = {"tools": tools_list}
                    elif method == "tools/call":
                        tool_name = params.get("name", "")
                        arguments = params.get("arguments", {})
                        # Parse site__toolname prefix
                        if "__" not in tool_name:
                            result = {"content": [{"type": "text",
                                        "text": f"Error: Tool '{tool_name}' missing site prefix. Use site__toolname."}],
                                      "isError": True}
                        else:
                            site, original = tool_name.split("__", 1)
                            client = bridge.clients.get(site)
                            if not client:
                                result = {"content": [{"type": "text",
                                            "text": f"Error: Site '{site}' not connected."}], "isError": True}
                            else:
                                text = client.call_tool(original, arguments)
                                result = {"content": [{"type": "text", "text": text}], "isError": False}
                    elif method == "ping":
                        result = {}
                    else:
                        self._respond(400, {"jsonrpc": "2.0", "id": req_id,
                                            "error": {"code": -32601, "message": f"Method not found: {method}"}})
                        return

                    self._respond(200, {"jsonrpc": "2.0", "id": req_id, "result": result})

                except Exception as e:
                    self._respond(500, {"jsonrpc": "2.0", "id": req_id,
                                        "error": {"code": -32603, "message": str(e)}})

            def do_GET(self):
                # Simple health check
                self._respond(200, {"status": "ok", "sites": list(bridge.clients.keys()),
                                    "tools": len(bridge.tools)})

            def _respond(self, status, data):
                body = json.dumps(data)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, format, *args):
                pass  # suppress HTTP logs

        return Handler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="FAC Bridge — MCP proxy for Frappe Assistant Core sites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python bridge.py serve              # serve all saved sites on :9090
              python bridge.py serve v15upgrade   # serve specific sites
              python bridge.py --add              # add a new site
              python bridge.py --list             # list saved sites
              python bridge.py --remove           # remove a site
        """),
    )
    sub = parser.add_subparsers(dest="command")

    serve_parser = sub.add_parser("serve", help="Start MCP proxy server")
    serve_parser.add_argument("sites", nargs="*", help="Sites to serve (default: all)")
    serve_parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help=f"Port (default: {DEFAULT_PORT})")

    parser.add_argument("--add", action="store_true", help="Add a new FAC site interactively")
    parser.add_argument("--list", action="store_true", help="List saved FAC sites")
    parser.add_argument("--remove", action="store_true", help="Remove a saved FAC site")

    args = parser.parse_args(argv)
    mgr = SiteManager()

    if args.list:
        sites = mgr.list_sites()
        if not sites:
            print("No FAC sites saved. Add one with: python bridge.py --add")
        else:
            print(f"\nSaved FAC sites ({len(sites)}):")
            for name, cfg in sites.items():
                host = urlparse(cfg["url"]).hostname or cfg["url"]
                auth = "OAuth" if cfg.get("access_token") else "API key"
                print(f"  {name:<22} {host}  ({auth})")
        return

    if args.remove:
        sites = mgr.list_sites()
        if not sites:
            print("No FAC sites to remove.")
            return
        name = _pick_site(sites)
        if name and _confirm(f"Remove \"{name}\"?"):
            mgr.remove(name)
            print(f"✓ \"{name}\" removed.")
        return

    if args.add:
        _add_site_interactive()
        return

    if args.command == "serve":
        bridge = MCPServerBridge(port=args.port, sites=args.sites or None)
        bridge.start()
        return

    # Default: no args → show help
    parser.print_help()


if __name__ == "__main__":
    main()
