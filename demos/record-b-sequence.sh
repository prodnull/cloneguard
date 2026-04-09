#!/usr/bin/env bash
# Record Demo B: Behavioral sequence detection
#
# Before recording:
#   1. Run: bash demos/setup-b-sequence.sh
#   2. Resize terminal to 100x30
#   3. Use a dark theme terminal
#
# During recording, type these commands:
#
#   1. cat /tmp/demo-cloneguard-b/.env
#      (show the sensitive file — AWS keys, DB creds)
#
#   2. uv run python demos/demo-b-sequence.py
#      (runs the two-step simulation: read allowed, curl blocked)

set -euo pipefail

CAST_FILE="demos/demo-b-sequence.cast"

echo "Starting recording in 3 seconds..."
sleep 3

asciinema rec "$CAST_FILE" \
  --title "CloneGuard Demo: Behavioral Sequence Detection" \
  --cols 100 \
  --rows 30

echo ""
echo "Recording saved to: $CAST_FILE"
echo "Review: asciinema play $CAST_FILE"
