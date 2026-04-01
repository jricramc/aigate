#!/usr/bin/env bash
# AiGate Claude Code Hook — PreToolUse
# Scans tool inputs for secrets before the tool executes.
# Returns JSON with permissionDecision: deny if secrets are found.

set -euo pipefail

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$INPUT" | jq -r '.tool_input // {} | tostring')

if [ -z "$TOOL_INPUT" ] || [ "$TOOL_INPUT" = "{}" ]; then
  exit 0
fi

# Pipe the full tool input JSON through aigate scanner
RESULT=$(echo "$TOOL_INPUT" | aigate scan - -j 2>/dev/null) || true

CLEAN=$(echo "$RESULT" | jq -r 'if .clean == false then "false" else "true" end')

if [ "$CLEAN" = "false" ]; then
  FINDINGS=$(echo "$RESULT" | jq -r '[.findings[] | .rule] | unique | join(", ")')
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
