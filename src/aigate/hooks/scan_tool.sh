#!/usr/bin/env bash
# AiGate Claude Code Hook — PreToolUse
# Scans tool inputs for secrets before the tool executes.
# Returns JSON with permissionDecision: deny if secrets are found.

set -euo pipefail

LOG_DIR="$HOME/.aigate"
LOG_FILE="$LOG_DIR/scan.log"
mkdir -p "$LOG_DIR"

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$INPUT" | jq -r '.tool_input // {} | tostring')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')

if [ -z "$TOOL_INPUT" ] || [ "$TOOL_INPUT" = "{}" ]; then
  exit 0
fi

# Pipe the full tool input JSON through aigate scanner
RESULT=$(echo "$TOOL_INPUT" | aigate scan - -j 2>/dev/null) || true

CLEAN=$(echo "$RESULT" | jq -r 'if .clean == false then "false" else "true" end')

if [ "$CLEAN" = "false" ]; then
  FINDINGS=$(echo "$RESULT" | jq -r '[.findings[] | .rule] | unique | join(", ")')
  DETAILS=$(echo "$RESULT" | jq -r '.findings[] | "  - [\(.rule)] \(.match_redacted)"')
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Log to file (JSON-lines)
  echo "$RESULT" | jq -c \
    --arg ts "$TIMESTAMP" \
    --arg event "PreToolUse" \
    --arg tool "$TOOL_NAME" \
    --arg session "$SESSION_ID" \
    --arg action "deny" \
    '{timestamp: $ts, event: $event, tool: $tool, session_id: $session, action: $action, findings: .findings}' \
    >> "$LOG_FILE"

  # Log to console
  echo "" >&2
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
  echo "🛡️  AiGate DENIED $TOOL_NAME ($TIMESTAMP)" >&2
  echo "$DETAILS" >&2
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
  echo "" >&2

  # Return deny to Claude Code
  jq -n \
    --arg tool "$TOOL_NAME" \
    --arg findings "$FINDINGS" \
    '{
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: ("AiGate: secrets detected in " + $tool + " input (" + $findings + "). Remove credentials and retry.")
      }
    }'
  exit 0
fi

exit 0
