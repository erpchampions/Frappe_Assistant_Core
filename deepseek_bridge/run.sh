#!/bin/bash
# FAC Bridge — start the MCP proxy server
cd "$(dirname "$0")"
python bridge.py serve "$@"
