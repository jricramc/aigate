#!/usr/bin/env bash
# aigate Claude Code Hook — UserPromptSubmit
# Scans the user's prompt for secrets before Claude processes it.
# Exit 0 = allow, Exit 2 = block (stderr shown to Claude as feedback)

set -euo pipefail

LOG_DIR="$HOME/.aigate"
LOG_FILE="$LOG_DIR/scan.log"
mkdir -p "$LOG_DIR"

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')

if [ -z "$PROMPT" ]; then
  exit 0
fi

# Pipe prompt through aigate scanner
RESULT=$(echo "$PROMPT" | aigate scan - -j 2>/dev/null) || true

CLEAN=$(echo "$RESULT" | jq -r 'if .clean == false then "false" else "true" end')

if [ "$CLEAN" = "false" ]; then
  DETAILS=$(echo "$RESULT" | jq -r '.findings[] | "  - [\(.rule)] \(.match_redacted)"')
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Log to file (JSON-lines)
  echo "$RESULT" | jq -c \
    --arg ts "$TIMESTAMP" \
    --arg event "UserPromptSubmit" \
    --arg session "$SESSION_ID" \
    --arg action "block" \
    '{timestamp: $ts, event: $event, session_id: $session, action: $action, findings: .findings}' \
    >> "$LOG_FILE"

  # Log to console
  echo "" >&2
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
  echo "🛡️  aigate BLOCKED prompt ($TIMESTAMP)" >&2
  echo "$DETAILS" >&2
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
  echo "" >&2
  echo "Remove the credentials from your prompt and try again." >&2
  exit 2
fi

exit 0
