#!/usr/bin/env bash
# Setup Demo C: Package hallucination squatting detection
# Shows CloneGuard catching an install of a non-existent PyPI package

set -euo pipefail

DEMO_DIR="/tmp/demo-cloneguard-c"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

git init -q
git config user.name "demo"
git config user.email "demo@example.com"

# Create a Python project where the agent might hallucinate a dependency
cat > README.md << 'EOF'
# my-web-app

A Flask web application with authentication.
EOF

cat > app.py << 'PYEOF'
from flask import Flask

app = Flask(__name__)

# TODO: Add authentication
# The AI agent might hallucinate a package like "flask-quickauth-helpers"
# which doesn't exist on PyPI — an attacker could squat this name
PYEOF

git add -A
git commit -q -m "Initial commit"

# Create the demo script that shows the hallucination check
cat > /tmp/demo-hallucination-check.py << 'PYEOF'
"""Demo: Package hallucination detection.

Simulates what happens when an AI agent tries to install a package
that doesn't exist on PyPI.
"""

from cloneguard.enforcement.registry import PackageRegistryClient

checker = PackageRegistryClient()

# The AI agent generated this install command
command = "pip install flask-quickauth-helpers"
print(f"Agent command: {command}")
print()

# Check if the packages exist
results = checker.check_packages_for_hallucination(command)

if results:
    for r in results:
        pkg = r.details["package"]
        registry = r.details["registry"]
        print(f"  [DETECTED] Package '{pkg}' not found on {registry}")
        print(f"  Confidence: {r.confidence}")
        print(f"  Reason: {r.details['reason']}")
        print()
        print("  If an attacker had registered this name first,")
        print("  you'd be running their code right now.")
else:
    print("  All packages found — no hallucination detected.")
PYEOF

echo ""
echo "Demo repo created at: $DEMO_DIR"
echo ""
echo "Run the hallucination check demo:"
echo "  uv run python /tmp/demo-hallucination-check.py"
