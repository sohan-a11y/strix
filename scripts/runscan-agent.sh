#!/usr/bin/env bash
# Run a Strix pentest headlessly through a coding agent (no Strix LLM key).
#
# Usage:
#   scripts/runscan-agent.sh <target> [quick|standard|deep] [model]
#
# The model is whatever OpenCode is configured with; Strix itself never calls
# an LLM API. Artifacts land in $STRIX_MCP_RUNS_DIR (default: <repo>/strix_runs).
set -euo pipefail

TARGET="${1:-}"
MODE="${2:-${STRIX_MCP_SCAN_MODE:-deep}}"
MODEL="${3:-}"

if [ -z "$TARGET" ]; then
    echo "usage: $0 <target> [quick|standard|deep] [provider/model]" >&2
    exit 2
fi

case "$MODE" in
    quick|standard|deep) ;;
    *) echo "mode must be quick, standard or deep (got '$MODE')" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$REPO/.venv/bin/python"
SERVER="$REPO/mcp/server.py"

command -v opencode >/dev/null 2>&1 || {
    echo "opencode is not on PATH. Install it from https://opencode.ai and re-run." >&2
    exit 1
}
[ -x "$PYTHON" ] || { echo "Python venv missing at $PYTHON. Run setup first." >&2; exit 1; }
[ -f "$SERVER" ] || { echo "MCP server missing at $SERVER." >&2; exit 1; }

if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    echo "warning: Docker daemon is not responding; start Docker Desktop before the run." >&2
fi

export STRIX_MCP_SCAN_MODE="$MODE"
TITLE="runscan-$(date +%Y%m%d-%H%M%S)"

PROMPT="$(cat <<EOF
Run the /runscan workflow for exactly this target: $TARGET
Scan mode: $MODE

Follow your system prompt. Start with strix_sandbox_health; if Docker or the
sandbox image is unavailable, report the exact fix and stop. Restate scope,
read or derive the threat model, and keep a short todo plan. Recon and map the
surface before attacking it, create throwaway accounts if auth is required,
record coverage as you assess each surface, and file only confirmed findings
with real captured evidence. Reconcile needs_follow_up coverage rows, then
call strix_finish_report exactly once.

Do not test anything outside $TARGET. If the target is unreachable, diagnose
once and stop. Finish with: findings by severity, one line each, the report
path, and the honest coverage gaps.
EOF
)"

ARGS=(run --agent pentest --auto --title "$TITLE")
[ -n "$MODEL" ] && ARGS+=(--model "$MODEL")
ARGS+=("$PROMPT")

echo "Strix agentic scan"
echo "  target : $TARGET"
echo "  mode   : $MODE"
echo "  runs   : ${STRIX_MCP_RUNS_DIR:-$REPO/strix_runs}"
echo "  session: $TITLE"
echo

cd "$REPO"
set +e
opencode "${ARGS[@]}"
CODE=$?
set -e

ROOT="${STRIX_MCP_RUNS_DIR:-$REPO/strix_runs}"
LATEST="$(ls -1dt "$ROOT"/runscan-* 2>/dev/null | head -n 1 || true)"
if [ -n "$LATEST" ]; then
    echo
    echo "Latest run: $LATEST"
    [ -f "$LATEST/penetration_test_report.md" ] && echo "Report:     $LATEST/penetration_test_report.md"
fi

exit "$CODE"
