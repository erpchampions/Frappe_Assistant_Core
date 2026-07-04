# DeepSeek ↔ Frappe Assistant Core Bridge

A terminal chat client that connects [DeepSeek](https://deepseek.com) models to your ERPNext system through the [Frappe Assistant Core](https://github.com/buildswithpaul/Frappe_Assistant_Core) MCP server.

Works just like Claude Desktop Connectors — add a site once, then refer to it by name.

## How It Works

```
You (terminal) ←→ Bridge ←→ DeepSeek API (thinking)
                     ↕
              Frappe MCP Server (tools)
                     ↕
              ERPNext / Frappe
```

1. The bridge discovers available tools from your Frappe MCP server
2. You type a message — it goes to DeepSeek along with the tool definitions
3. DeepSeek decides whether to respond directly or call a tool
4. If it calls a tool, the bridge executes it via MCP and feeds the result back
5. The loop continues until DeepSeek produces a final text response

## Quick Start

### 1. Install dependencies

```bash
cd deepseek_bridge
pip install -r requirements.txt
```

### 2. Set your DeepSeek API key (one-time)

Add this to your `~/.bashrc` so it's always available:

```bash
export DEEPSEEK_API_KEY="sk-your-deepseek-key"
```

Get a key at [platform.deepseek.com](https://platform.deepseek.com).

### 3. Add a site (one-time per site)

```bash
python bridge.py --add
```

Paste your **FAC Endpoint URL** (from the FAC Admin page). The bridge auto-detects the site name.

Then choose your auth method:

**Option 1: OAuth (browser login)** — a browser opens, you log into your Frappe site, done. No keys to copy.

**Option 2: API Key + Secret** — generate in Frappe: **User → API Access → Generate Keys**, paste them in.

That's it. Credentials are saved to `~/.fac_bridge/sites.json` (permissions `0600`).

### 4. Connect and chat

```bash
# Connect to a specific site
python bridge.py v15upgrade

# Or pick from a menu of saved sites
python bridge.py
```

```
You: List all customers in the system

DeepSeek: Here are the customers I found:
         • Acme Corp — acme@example.com
         • Globex Inc — info@globex.com
         ...

You: Create a new customer "Stark Industries" with email tony@stark.com

DeepSeek: [creates via create_document tool] Done!
         Customer "Stark Industries" created successfully.
```

## Managing Sites

```bash
python bridge.py --add       # Add a new site
python bridge.py --list      # Show saved sites
python bridge.py --remove    # Remove a site
python bridge.py v15upgrade  # Connect directly to a site
python bridge.py             # Pick from a menu
```

Sites are stored in `~/.fac_bridge/sites.json` with restricted permissions (`0600`).

## Chat Commands

| Command     | Description                     |
|-------------|---------------------------------|
| `/tools`    | List all available MCP tools    |
| `/clear`    | Clear conversation history      |
| `/history`  | Show message count in history   |
| `/help`     | Show available commands         |
| `/exit`     | Quit the bridge                 |

## Configuration Reference

All settings can also be provided via environment variables or CLI flags (they override saved sites):

| CLI Flag             | Env Variable               | Description              |
|----------------------|----------------------------|--------------------------|
| `--mcp-url`          | `FRAUD_ASSISTANT_MCP_URL`  | MCP endpoint URL         |
| `--api-key`          | `FRAUD_ASSISTANT_API_KEY`  | Frappe API key           |
| `--api-secret`       | `FRAUD_ASSISTANT_API_SECRET` | Frappe API secret     |
| `--deepseek-api-key` | `DEEPSEEK_API_KEY`         | DeepSeek API key         |
| `--model`            | `DEEPSEEK_MODEL`           | Model (default: deepseek-chat) |
| `--verbose`, `-v`    | —                          | Show tool details on connect |

## Models

| Model | Description |
|-------|-------------|
| `deepseek-chat` | General-purpose chat (default, best value) |
| `deepseek-reasoner` | Reasoning model for complex analysis |

## Architecture Notes

- **Your ERP data never goes to DeepSeek** — only the chat messages and tool results are sent as context.
- **Tool execution happens on your Frappe server** — the bridge just relays requests and responses.
- **Conversation history** is kept in memory only (not persisted to disk).
- The bridge limits tool-calling rounds to 25 to prevent infinite loops.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Cannot reach MCP server" | Check that the Frappe server is running and the URL is correct |
| "Authentication failed (401)" | Verify your Frappe API key and secret — regenerate if needed |
| "Access denied (403)" | Check "Assistant Enabled" is checked on your Frappe User record |
| "DeepSeek API error" | Verify your DeepSeek API key and account balance |
| No tools discovered | Check that plugins are enabled in Assistant Core Settings |
| "Maximum tool-calling rounds" | The task is too complex — try breaking it into smaller requests |

## License

This bridge is part of Frappe Assistant Core, licensed under AGPL-3.0.
