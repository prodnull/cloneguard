#!/usr/bin/env bash
# Record Demo A: .clinerules attack detection
#
# Before recording:
#   1. Run: bash demos/setup-a-clinerules.sh
#   2. Resize terminal to 100x30 for clean recording
#   3. Use a dark theme terminal

set -euo pipefail

DEMO_DIR="/tmp/demo-cloneguard-a"
CAST_FILE="demos/demo-a-clinerules.cast"

echo "Starting recording in 3 seconds..."
echo "Commands to type during recording:"
echo ""
echo '  1. cd /tmp/demo-cloneguard-a'
echo '  2. ls -la                          # show normal-looking project'
echo '  3. cat .clinerules                  # show the hidden payload'
echo '  4. cloneguard scan .                # CloneGuard catches it'
echo ""
echo "Pause briefly between commands for readability."
echo ""

sleep 3

asciinema rec "$CAST_FILE" \
  --title "CloneGuard Demo: .clinerules Attack Detection" \
  --cols 100 \
  --rows 30

echo ""
echo "Recording saved to: $CAST_FILE"
echo "Review: asciinema play $CAST_FILE"
echo "Upload: asciinema upload $CAST_FILE"
