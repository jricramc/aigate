#!/usr/bin/env bash
# aigate Claude Code Hook — PostToolUse
# Fires after Write and Edit tools. Scans the written/edited file for
# hardcoded secrets and feeds findings back to the agent so it can fix them.
#
# Stdin: JSON with tool_name, tool_input, tool_output, session_id
# Stdout: feedback text for the agent (if secrets found)
# Stderr: console logging

set -euo pipefail

LOG_DIR="$HOME/.aigate"
LOG_FILE="$LOG_DIR/scan.log"
mkdir -p "$LOG_DIR"

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')

# Only scan after file-writing tools
case "$TOOL_NAME" in
  Write|Edit|write|edit) ;;
  *) exit 0 ;;
esac

# Extract the file path from tool input
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty')

if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

# Skip binary/non-code files
case "$FILE_PATH" in
  *.png|*.jpg|*.jpeg|*.gif|*.ico|*.woff|*.woff2|*.ttf|*.eot|*.svg|*.pdf|*.zip|*.tar|*.gz|*.bz2)
    exit 0
    ;;
esac

# Scan the file that was just written/edited
RESULT=$(aigate scan "$FILE_PATH" -j 2>/dev/null) || true

if [ -z "$RESULT" ]; then
  exit 0
fi

CLEAN=$(echo "$RESULT" | jq -r 'if .clean == false then "false" else "true" end')

if [ "$CLEAN" = "false" ]; then
  FINDINGS=$(echo "$RESULT" | jq -r '[.findings[] | .rule] | unique | join(", ")')
  DETAILS=$(echo "$RESULT" | jq -r '.findings[] | "  - [\(.rule)] \(.match_redacted)"')
  COUNT=$(echo "$RESULT" | jq -r '.findings | length')
  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Log to file (JSON-lines)
  echo "$RESULT" | jq -c \
    --arg ts "$TIMESTAMP" \
    --arg event "PostToolUse" \
    --arg tool "$TOOL_NAME" \
    --arg file "$FILE_PATH" \
    --arg session "$SESSION_ID" \
    --arg action "warn" \
    '{timestamp: $ts, event: $event, tool: $tool, file: $file, session_id: $session, action: $action, findings: .findings}' \
    >> "$LOG_FILE"

  # Log to console
  echo "" >&2
  echo "aigate: detected $COUNT secret(s) in $FILE_PATH" >&2
  echo "$DETAILS" >&2
  echo "" >&2

  # Return feedback to the agent
  echo "aigate detected $COUNT hardcoded secret(s) in $FILE_PATH after writing. Rules triggered: $FINDINGS. Please fix the code to use environment variables instead of hardcoded credentials. Store the actual secret values in a .env file."
  exit 0
fi

exit 0
