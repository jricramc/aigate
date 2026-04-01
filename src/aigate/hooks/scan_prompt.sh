#!/usr/bin/env bash
# AiGate Claude Code Hook — UserPromptSubmit
# Scans the user's prompt for secrets before Claude processes it.
# Exit 0 = allow, Exit 2 = block (stderr shown to Claude as feedback)

set -euo pipefail

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty')

if [ -z "$PROMPT" ]; then
  exit 0
fi

# Pipe prompt through aigate scanner
RESULT=$(echo "$PROMPT" | aigate scan - -j 2>/dev/null) || true

CLEAN=$(echo "$RESULT" | jq -r 'if .clean == false then "false" else "true" end')

if [ "$CLEAN" = "false" ]; then
  # Extract finding details for the error message
  DETAILS=$(echo "$RESULT" | jq -r '.findings[] | "  - [\(.rule)] \(.match_redacted)"')
  echo "AiGate blocked this prompt — secrets detected:" >&2
  echo "$DETAILS" >&2
  echo "" >&2
  echo "Remove the credentials from your prompt and try again." >&2
  exit 2
fi

exit 0
