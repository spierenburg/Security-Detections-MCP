#!/bin/sh
# Security-Detections-MCP entrypoint.
# MCP stdio contract: stdout must be pure JSON-RPC; all logging to stderr.
set -eu

MAX_AGE="${FRESHNESS_MAX_AGE_DAYS:-14}"
TRANSPORT="${MCP_TRANSPORT:-stdio}"
PORT="${MCP_HTTP_PORT:-8000}"
HTTP_PATH="${MCP_HTTP_PATH:-/mcp}"
HEALTH_PATH="${MCP_HEALTH_PATH:-/healthz}"

PRESENT=0

check() {
  name="$1"
  paths="$2"
  [ -z "${paths:-}" ] && return 0
  IFS=','
  for p in $paths; do
    unset IFS
    if [ ! -d "$p" ] || [ -z "$(find "$p" -type f 2>/dev/null | head -n1)" ]; then
      echo "[entrypoint] WARN: $name source empty or missing at $p" >&2
      continue
    fi
    PRESENT=$((PRESENT + 1))
    if [ -z "$(find "$p" -type f -mtime -"$MAX_AGE" 2>/dev/null | head -n1)" ]; then
      echo "[entrypoint] WARN: $name at $p has no files modified in last $MAX_AGE days" >&2
    fi
  done
}

check SIGMA    "$SIGMA_PATHS"
check SPLUNK   "$SPLUNK_PATHS"
check STORY    "$STORY_PATHS"
check ELASTIC  "$ELASTIC_PATHS"
check KQL      "$KQL_PATHS"
check SUBLIME  "$SUBLIME_PATHS"
check CQL_HUB  "$CQL_HUB_PATHS"

if [ ! -f "$ATTACK_STIX_PATH" ]; then
  echo "[entrypoint] WARN: ATT&CK STIX missing at $ATTACK_STIX_PATH — actor/technique lookups degraded" >&2
fi

if [ "$PRESENT" -eq 0 ]; then
  echo "[entrypoint] FATAL: zero detection sources populated — rules-refresher has not completed a cycle yet" >&2
  exit 1
fi

if [ -r /etc/security-detections-mcp.build-info ]; then
  echo "[entrypoint] $(cat /etc/security-detections-mcp.build-info)" >&2
fi

case "$TRANSPORT" in
  stdio)
    echo "[entrypoint] starting in stdio mode" >&2
    exec security-detections-mcp "$@"
    ;;
  http|streamableHttp|streamable)
    echo "[entrypoint] starting supergateway streamableHttp on :$PORT$HTTP_PATH" >&2
    exec supergateway \
      --stdio "security-detections-mcp" \
      --outputTransport streamableHttp \
      --port "$PORT" \
      --streamableHttpPath "$HTTP_PATH" \
      --healthEndpoint "$HEALTH_PATH"
    ;;
  *)
    echo "[entrypoint] FATAL: unknown MCP_TRANSPORT=$TRANSPORT (expected: stdio|http)" >&2
    exit 2
    ;;
esac
