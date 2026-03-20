#!/usr/bin/env bash
# Stop hook: checks if there are uncommitted changes that might need review.
# Surfaces a reminder about security review for significant changes.
set -euo pipefail

cd "$CLAUDE_PROJECT_DIR"

# Count modified Rust files
CHANGED=$(git diff --name-only -- '*.rs' 2>/dev/null | wc -l)
STAGED=$(git diff --cached --name-only -- '*.rs' 2>/dev/null | wc -l)
TOTAL=$((CHANGED + STAGED))

if [ "$TOTAL" -eq 0 ]; then
  exit 0
fi

# Check if security-sensitive files were touched
SECURITY_FILES="auth\.rs|crypto\.rs|ssh|peer\.rs|socket\.rs|session\.rs|state\.rs|prompt|config\.rs"
SENSITIVE=$(git diff --name-only -- '*.rs' 2>/dev/null | grep -cE "$SECURITY_FILES" || true)
SENSITIVE_STAGED=$(git diff --cached --name-only -- '*.rs' 2>/dev/null | grep -cE "$SECURITY_FILES" || true)
SENSITIVE_TOTAL=$((SENSITIVE + SENSITIVE_STAGED))

OUTPUT=""
if [ "$SENSITIVE_TOTAL" -gt 0 ]; then
  OUTPUT="$SENSITIVE_TOTAL security-sensitive file(s) modified. Consider running /security-review before committing."
fi

if [ -n "$OUTPUT" ]; then
  echo "{\"stopReason\":\"$OUTPUT\"}"
fi

exit 0
