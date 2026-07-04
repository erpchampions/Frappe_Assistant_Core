# FAC Bridge — MCP Proxy Server

Exposes Frappe Assistant Core tools from your sites as a local MCP server.
Connect Claude Code to it — all your FAC tools appear alongside Claude's built-in tools.

## How it works

```
Claude Code ──MCP──> Bridge (:9090) ──MCP──> v15upgrade.jh.frappe.cloud
                                    ──MCP──> peas-staging.jh.frappe.cloud
                                    ──MCP──> localhost:8020
```

Tools are prefixed by site name so they don't collide:
- `v15upgrade__list_documents`
- `peas_staging__list_documents`
- `local__list_documents`

## Setup

### 1. Install

```bash
cd deepseek_bridge
pip install -r requirements.txt
```

### 2. Add your FAC sites (one-time each)

```bash
python bridge.py --add
# → paste FAC endpoint URL
# → choose OAuth (browser login) or API key
# → done
```

```bash
python bridge.py --list    # see saved sites
python bridge.py --remove  # remove a site
```

### 3. Start the bridge

```bash
python bridge.py serve              # all saved sites
python bridge.py serve v15upgrade   # specific sites
python bridge.py serve --port 9090  # custom port
```

### 4. Add to Claude Code

Add MCP connector: `http://localhost:9090`

That's it. Your FAC tools appear in Claude Code, prefixed by site name.

## Commands

```bash
python bridge.py serve [sites]   # Start MCP proxy server
python bridge.py --add           # Add a new site
python bridge.py --list          # List saved sites
python bridge.py --remove        # Remove a site
```

## Configuration

Sites stored in `~/.fac_bridge/sites.json` (permissions 0600).
