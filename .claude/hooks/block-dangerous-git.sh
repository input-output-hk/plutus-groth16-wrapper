#!/usr/bin/env bash
# PreToolUse hook: blocks dangerous git and gh commands

INPUT=$(cat)
if command -v jq &>/dev/null; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
else
  COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null || true)
fi

block() {
  echo "BLOCKED: You do not have authority to run this command: $COMMAND" >&2
  exit 2
}

# git push (all variants)
echo "$COMMAND" | grep -qE '^\s*git\s+push(\s|$)' && block

# git reset --hard
echo "$COMMAND" | grep -qE '^\s*git\s+reset\s+--hard' && block

# git clean -f / -fd / -fx etc.
echo "$COMMAND" | grep -qE '^\s*git\s+clean\s+.*-[a-zA-Z]*f' && block

# git branch -D
echo "$COMMAND" | grep -qE '^\s*git\s+branch\s+.*-D' && block

# git checkout . or git restore .
echo "$COMMAND" | grep -qE '^\s*git\s+(checkout|restore)\s+\.' && block

# gh repo delete
echo "$COMMAND" | grep -qE '^\s*gh\s+repo\s+delete' && block

# gh release delete
echo "$COMMAND" | grep -qE '^\s*gh\s+release\s+delete' && block

# gh issue delete
echo "$COMMAND" | grep -qE '^\s*gh\s+issue\s+delete' && block

# gh pr close
echo "$COMMAND" | grep -qE '^\s*gh\s+pr\s+close' && block

# gh run cancel
echo "$COMMAND" | grep -qE '^\s*gh\s+run\s+cancel' && block

exit 0
