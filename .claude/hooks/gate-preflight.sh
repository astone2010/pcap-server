#!/usr/bin/env bash
# dev-skills gate pre-flight — PreToolUse hook
#
# Blocks git write operations when the gates the operation requires have not
# passed. This is the deterministic half of gate enforcement: SKILL.md asks
# Claude to check the gates, this makes the check unskippable for anything
# Claude executes itself.
#
# Source of truth is .claude/dev-skills-gates.md (SKILL.md Section 2). A gate
# counts as satisfied when its line carries ✅ (passed) or ➖ (N/A).
#
# Install: see hooks/README.md
# Bypass:  DEV_SKILLS_GATE_HOOK=off
#
# Fails closed. Per SKILL.md Section 4, when something unexpected happens we
# deny rather than allow.

set -uo pipefail

STATE_REL=".claude/dev-skills-gates.md"

# --- output helpers -----------------------------------------------------------

# deny <reason>
deny() {
  # Emit the JSON by hand so the hook has no dependency on jq for output.
  local reason="$1"
  reason="${reason//\\/\\\\}"
  reason="${reason//\"/\\\"}"
  reason="${reason//$'\n'/\\n}"
  reason="${reason//$'\t'/\\t}"
  reason="${reason//$'\r'/}"
  # Strip any remaining raw control character — it would make the JSON invalid.
  # Real newlines and tabs became two-character escapes above, so this is safe.
  reason="$(printf '%s' "$reason" | tr -d '\000-\037')"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$reason"
  exit 0
}

# No opinion — the tool call proceeds through the normal permission flow.
allow() { exit 0; }

[ "${DEV_SKILLS_GATE_HOOK:-on}" = "off" ] && allow

# --- read hook input ----------------------------------------------------------

INPUT="$(cat)"
[ -z "$INPUT" ] && allow

# Extract a top-level or nested field. jq preferred, python3 as fallback.
json_get() {
  local path="$1"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$INPUT" | jq -r "$path // empty" 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s' "$INPUT" | python3 -c '
import json,sys
path=sys.argv[1].lstrip(".").split(".")
try:
    cur=json.load(sys.stdin)
except Exception:
    sys.exit(0)
for k in path:
    if isinstance(cur,dict) and k in cur:
        cur=cur[k]
    else:
        sys.exit(0)
if cur is not None:
    sys.stdout.write(cur if isinstance(cur,str) else json.dumps(cur))
' "$path" 2>/dev/null
  else
    printf '__NOPARSER__'
  fi
}

TOOL_NAME="$(json_get '.tool_name')"
if [ "$TOOL_NAME" = "__NOPARSER__" ]; then
  deny "dev-skills gate hook cannot run: neither jq nor python3 is available to parse the hook payload. This hook fails closed, so git write operations are blocked until one is installed. Install jq (or python3), or set DEV_SKILLS_GATE_HOOK=off to disable gate enforcement."
fi
[ -z "$TOOL_NAME" ] && allow

# --- classify the operation ---------------------------------------------------
# OP_LABEL: what to call it in the denial message
# REQUIRED: gates that must be ✅ or ➖ before it may proceed

OP_LABEL=""
REQUIRED=""

case "$TOOL_NAME" in
  Bash)
    CMD="$(json_get '.tool_input.command')"
    [ -z "$CMD" ] && allow
    # Strip quoting so `git commit -m "..."` and friends match predictably.
    SCAN="$(printf '%s' "$CMD" | tr '\n' ' ')"

    if printf '%s' "$SCAN" | grep -qE '(^|[;&|(]|&&|\|\|)[[:space:]]*(gh[[:space:]]+release[[:space:]]+create|gh[[:space:]]+pr[[:space:]]+merge|git[[:space:]]+tag[[:space:]]+[^-])' \
       || printf '%s' "$SCAN" | grep -qE 'git[[:space:]]+push[[:space:]].*(--tags|[[:space:]]v[0-9]+\.[0-9]+)' \
       || printf '%s' "$SCAN" | grep -qE 'git[[:space:]]+push[[:space:]]+origin[[:space:]]+(main|master)([[:space:]]|$)'; then
      OP_LABEL="a release operation (tag / merge / publish)"
      REQUIRED="VERSION BUILD SECURITY DOCS RELEASE"
    elif printf '%s' "$SCAN" | grep -qE 'gh[[:space:]]+pr[[:space:]]+create'; then
      OP_LABEL="opening a pull request (Gate 5)"
      REQUIRED="VERSION BUILD SECURITY DOCS"
    elif printf '%s' "$SCAN" | grep -qE '(^|[;&|(]|&&|\|\|)[[:space:]]*git[[:space:]]+(commit|push)([[:space:]]|$)'; then
      OP_LABEL="a work commit / push"
      REQUIRED="SECURITY"
    else
      allow
    fi
    ;;
  mcp__github__merge_pull_request)
    OP_LABEL="merging a pull request (Gate 6)"
    REQUIRED="VERSION BUILD SECURITY DOCS RELEASE"
    ;;
  mcp__github__create_pull_request)
    OP_LABEL="opening a pull request (Gate 5)"
    REQUIRED="VERSION BUILD SECURITY DOCS"
    ;;
  mcp__github__push_files|mcp__github__create_or_update_file|mcp__github__delete_file)
    OP_LABEL="a work commit / push"
    REQUIRED="SECURITY"
    ;;
  *)
    allow
    ;;
esac

# --- locate the gate state file -----------------------------------------------

CWD="$(json_get '.cwd')"
[ -n "$CWD" ] && [ -d "$CWD" ] && cd "$CWD" 2>/dev/null

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$ROOT" ]; then
  ROOT="${CLAUDE_PROJECT_DIR:-$PWD}"
fi
STATE="$ROOT/$STATE_REL"

if [ ! -f "$STATE" ]; then
  deny "🚫 GATE PRE-FLIGHT — no gate state file.

Blocked: $OP_LABEL
Missing: $STATE_REL

The dev-skills gate state file does not exist, so there is no evidence any gate has run. Per SKILL.md Section 2, unknown is never \"passed.\"

Do this before retrying:
1. Re-derive gate state from evidence (SKILL.md Section 2 re-derivation table) — do not assume a gate passed because it feels like it did.
2. Run whichever of these gates is still pending: $REQUIRED
3. Write $STATE_REL with the resulting state.

Do not work around this by editing the state file to say a gate passed when it did not."
fi

# --- evaluate the required gates ----------------------------------------------
# A gate is satisfied when its line carries ✅ (passed) or ➖ (N/A).
# Byte-literal matching via grep -F, so locale settings can't break it.

BLOCKING=""
for gate in $REQUIRED; do
  line="$(grep -E "(^|[[:space:]])${gate}([[:space:]]|$)" "$STATE" 2>/dev/null | head -1)"
  if [ -z "$line" ]; then
    BLOCKING="$BLOCKING
  - $gate — not present in $STATE_REL (treated as pending)"
    continue
  fi
  if printf '%s' "$line" | grep -qF '✅'; then continue; fi
  if printf '%s' "$line" | grep -qF '➖'; then continue; fi
  status="$(printf '%s' "$line" | sed "s/^[[:space:]]*//")"
  BLOCKING="$BLOCKING
  - $status"
done

# --- BUILD gate: local-artifact-handoff annotation ----------------------------
# GATE_REFERENCE.md Gate 2 requires Claude to offer a way to try a compiled
# artifact (Docker image, Windows .exe, Android .apk) by hand before BUILD
# passes -- a conversational step this hook cannot observe directly. What it
# can check, the same way every other gate here is checked, is whether the
# tracker line says it happened. A BUILD line marked ✅ with no "handoff"
# annotation, in a repo that plainly produces one of these artifact types, is
# textual evidence the offer was skipped, not proof it was made.
produces_compiled_artifact() {
  find "$ROOT" -maxdepth 4 \
    \( -path '*/.git' -o -path '*/node_modules' -o -path '*/.venv' -o -path '*/venv' -o -path '*/build' -o -path '*/dist' \) -prune -o \
    \( -iname 'Dockerfile' -o -iname '*.csproj' -o -iname '*.sln' -o -iname 'AndroidManifest.xml' -o -iname 'build.gradle' -o -iname 'build.gradle.kts' \) -print \
    2>/dev/null | head -1 | grep -q .
}

if printf '%s' "$REQUIRED" | grep -qw BUILD; then
  build_line="$(grep -E "(^|[[:space:]])BUILD([[:space:]]|$)" "$STATE" 2>/dev/null | head -1)"
  if printf '%s' "$build_line" | grep -qF '✅' \
     && ! printf '%s' "$build_line" | grep -qiF 'handoff' \
     && produces_compiled_artifact; then
    BLOCKING="$BLOCKING
  - BUILD — ✅ but no local-artifact-handoff annotation. This repo has a Docker/.exe/.apk build signal (Dockerfile, .csproj/.sln, or an Android Gradle project). GATE_REFERENCE.md Gate 2 requires offering the user a way to try the real artifact before this gate passes. Add \"handoff offered\", \"handoff declined\", or \"handoff n/a (remote container / Termux session)\" to the BUILD line, then retry."
  fi
fi

[ -z "$BLOCKING" ] && allow

TRACKER="$(sed 's/^/  /' "$STATE" 2>/dev/null)"

deny "🚫 GATE PRE-FLIGHT BLOCKED

Blocked: $OP_LABEL
Required gates: $REQUIRED

Not yet ✅ or ➖ N/A:$BLOCKING

Current state ($STATE_REL):
$TRACKER

Run the blocking gate(s) per SKILL.md, update $STATE_REL, then retry.

A gate leaves the workflow only two ways: it passes (✅), or it is marked ➖ N/A for a structural reason stated on the tracker — no build system, no compiled artifact, no app UI. \"We'll do it later\" is not N/A. Do not edit the state file to clear a gate you did not run."
