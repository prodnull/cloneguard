#!/usr/bin/env bash
# Record Demo C: Package hallucination squatting detection
#
# Before recording:
#   1. Run: bash demos/setup-c-hallucination.sh
#   2. Resize terminal to 100x30
#   3. Use a dark theme terminal
#
# During recording, type these commands:
#
#   1. echo "AI agent is writing a Flask app and needs auth..."
#      echo "Agent generates: pip install flask-auth-utils"
#      echo ""
#
#   2. pip install flask-auth-utils
#      (this will fail — package doesn't exist. Show the error briefly.)
#
#   3. echo "But what if an attacker had registered that name first?"
#      echo "CloneGuard checks before the install runs:"
#      echo ""
#
#   4. uv run python /tmp/demo-hallucination-check.py
#      (shows the detection)

set -euo pipefail

CAST_FILE="demos/demo-c-hallucination.cast"

echo "Starting recording in 3 seconds..."
sleep 3

asciinema rec "$CAST_FILE" \
  --title "CloneGuard Demo: Package Hallucination Squatting" \
  --cols 100 \
  --rows 30

echo ""
echo "Recording saved to: $CAST_FILE"
echo "Review: asciinema play $CAST_FILE"
