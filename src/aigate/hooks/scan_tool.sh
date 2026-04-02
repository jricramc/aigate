#!/usr/bin/env bash
# aigate Claude Code Hook — PreToolUse
# Scans tool inputs for secrets. If found, redacts them and returns
# updatedInput so the tool runs with sanitized values.
# Real credentials are saved to .env automatically.

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

# Scan with redact mode — returns redacted_text + saves to .env
RESULT=$(echo "$TOOL_INPUT" | aigate scan - -j -r 2>/dev/null) || true

CLEAN=$(echo "$RESULT" | jq -r 'if .clean == false then "false" else "true" end')

if [ "$CLEAN" = "false" ]; then
  REDACTED_TEXT=$(echo "$RESULT" | jq -r '.redacted_text // empty')
  FINDINGS=$(echo "$RESULT" | jq -r '[.redactions[] | .rule] | unique | join(", ")')
  REDACTION_DETAILS=$(echo "$RESULT" | jq -r '.redactions[] | "  - \(.match_redacted) → \(.placeholder)"')
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Log to file (JSON-lines)
  echo "$RESULT" | jq -c \
    --arg ts "$TIMESTAMP" \
    --arg event "PreToolUse" \
    --arg tool "$TOOL_NAME" \
    --arg session "$SESSION_ID" \
    --arg action "redact" \
    '{timestamp: $ts, event: $event, tool: $tool, session_id: $session, action: $action, redactions: .redactions}' \
    >> "$LOG_FILE"

  # Log to console
  echo "" >&2
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
  echo "🛡️  aigate REDACTED secrets in $TOOL_NAME ($TIMESTAMP)" >&2
  echo "$REDACTION_DETAILS" >&2
  echo "  Credentials saved to .env" >&2
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
  echo "" >&2

  # Parse the redacted text back as JSON and return as updatedInput
  UPDATED_INPUT=$(echo "$REDACTED_TEXT" | jq '.' 2>/dev/null) || UPDATED_INPUT=""

  if [ -n "$UPDATED_INPUT" ] && [ "$UPDATED_INPUT" != "null" ]; then
    # Return allow + rewritten input
    jq -n \
      --argjson updated "$UPDATED_INPUT" \
      '{
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "allow",
          updatedInput: $updated
        }
      }'
  else
    # Redacted text wasn't valid JSON — fall back to deny
    jq -n \
      --arg tool "$TOOL_NAME" \
      --arg findings "$FINDINGS" \
      '{
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: ("aigate: secrets detected in " + $tool + " input (" + $findings + "). Remove credentials and retry.")
        }
      }'
  fi
  exit 0
fi

exit 0
