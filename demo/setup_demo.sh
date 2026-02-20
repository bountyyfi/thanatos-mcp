#!/bin/bash
# Thanatos MCP - Demo Setup
# Security Research PoC - Responsible Disclosure Only

echo "Setting up Thanatos demo environment..."

mkdir -p ~/.thanatos
export THANATOS_DEMO=true
export THANATOS_DB=~/.thanatos/demo.db

echo "Demo environment ready."
echo "Set THANATOS_DEMO=true in your MCP server env config."
echo "Start a netcat listener: nc -l 9999"
