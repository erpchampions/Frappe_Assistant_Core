#!/bin/bash
# DeepSeek + Frappe Assistant Core Bridge — convenience launcher
# Source this file or run it directly:
#   source run.sh
#   or
#   bash run.sh

export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-sk-3afc7092dec241b9a8b3163c95e78be7}"
export FRAUD_ASSISTANT_MCP_URL="http://localhost:8020/api/method/frappe_assistant_core.api.fac_endpoint.handle_mcp"
export FRAUD_ASSISTANT_API_KEY="131cee53e47363fa"
export FRAUD_ASSISTANT_API_SECRET="vrjztB5akvpEWtUtN-F7gCFvaakmknEczD2NdjCV8jw"

cd "$(dirname "$0")"
python bridge.py "$@"
