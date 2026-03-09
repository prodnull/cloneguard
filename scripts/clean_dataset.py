#!/usr/bin/env python3
"""Clean the training dataset and add missing benign samples.

Fixes identified by independent audit (2026-03-09):
1. Remove mislabeled malicious samples (benign headings, commit messages, code constructs)
2. Add long benign samples (READMEs, licenses, docs)
3. Add benign imperative instructions, SQL, .env examples
4. Review and remove sub-30-char malicious fragments without attack semantics

Writes cleaned dataset to data/training/dataset.jsonl (overwrites in place).
Writes audit log to data/training/cleanup-audit.log.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "data" / "training" / "dataset.jsonl"
AUDIT_LOG = ROOT / "data" / "training" / "cleanup-audit.log"


def load_dataset(path: Path) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            records.append(json.loads(line))
    return records


def is_benign_heading(text: str) -> bool:
    """Detect markdown headings with no attack content."""
    text = text.strip()
    if not re.match(r"^#{1,4}\s", text):
        return False
    attack_words = [
        "ignore", "override", "inject", "exfil", "bypass", "steal",
        "reveal", "secret", "credential", "token", "password", "hack",
        "exploit", "payload", "malicious", "attack", "hijack", "backdoor",
        "disable", "skip", "permission", "sudo", "curl", "wget", "eval(",
    ]
    lower = text.lower()
    return len(text) < 80 and not any(w in lower for w in attack_words)


def is_benign_commit_message(text: str) -> bool:
    """Detect conventional commit messages."""
    return bool(re.match(
        r"^(feat|fix|bugfix|doc|docs|test|refactor|chore|ci|style|perf|build|revert)(\(.+?\))?:\s",
        text.strip(),
        re.IGNORECASE,
    )) and len(text) < 100


def is_benign_bold_reference(text: str) -> bool:
    """Detect bold-wrapped filename references."""
    text = text.strip()
    return bool(re.match(r"^\*\*[\d.]*\s*[A-Za-z_/.-]+", text)) and len(text) < 100


def is_benign_code_construct(text: str) -> bool:
    """Detect standard code constructs with no attack semantics."""
    text = text.strip()
    if len(text) > 80:
        return False
    benign_patterns = [
        r"^print\(",
        r"^console\.(log|error|warn)\(",
        r"^#include\s+<",
        r"^import\s+\w+",
        r"^from\s+\w+\s+import",
        r"^export\s+(interface|class|function|const|type)\s",
        r"^fn\s+\w+\(",
        r"^func\s+\w+\(",
        r"^def\s+\w+\(",
        r"^class\s+\w+",
        r"^db\.\w+\(",
        r'^"[\w@^~.]+"\s*:\s*\{',
        r"^assert\s+",
        r"^return\s+",
    ]
    attack_words = [
        "ignore", "override", "inject", "exfil", "bypass", "steal",
        "reveal", "secret", "credential", "token", "password",
        "curl", "wget", "eval(", "exec(", "system(",
    ]
    lower = text.lower()
    if any(w in lower for w in attack_words):
        return False
    return any(re.match(p, text) for p in benign_patterns)


def is_benign_yaml_fragment(text: str) -> bool:
    """Detect neutral YAML fragments."""
    text = text.strip()
    return bool(re.match(r"^(title|name|description|version|author):\s", text)) and len(text) < 80


def is_fragment_without_attack_semantics(text: str) -> bool:
    """Detect sub-30-char malicious-labeled fragments with no attack content."""
    text = text.strip()
    if len(text) >= 30:
        return False
    attack_words = [
        "ignore", "override", "inject", "exfil", "bypass", "steal",
        "reveal", "secret", "credential", "token", "password", "hack",
        "exploit", "payload", "malicious", "attack", "hijack", "backdoor",
        "disable", "skip", "permission", "sudo", "curl", "wget", "eval",
        "exec", "system", "base64", "decode", "encode", "obey", "comply",
        "instruction", "command", "execute", "shell", "bash", "ssh",
        "env", "key", "api_key", "aws_", "npm_token",
    ]
    lower = text.lower()
    if any(w in lower for w in attack_words):
        return False
    if re.match(r"^[\w./:-]+\.?\w*:?$", text):
        return True
    if re.match(r"^\*\*[\w./:-]+\*\*$", text):
        return True
    return False


# --- New benign samples to add ---

BENIGN_IMPERATIVE_INSTRUCTIONS = [
    "Set the timeout to 30 seconds for all API calls.",
    "Delete the temporary files after the build completes.",
    "Move the old logs to the archive directory.",
    "Update the version number in package.json before releasing.",
    "Run the migration scripts before starting the server.",
    "Copy the configuration template to config.yaml and edit it.",
    "Install the development dependencies with npm install.",
    "Please review the pull request and leave your feedback.",
    "Add the new endpoint to the API documentation.",
    "Remove the deprecated functions from the utils module.",
    "Set up the database connection using the provided credentials.",
    "Clean up the unused imports in the main module.",
    "Merge the feature branch into develop when tests pass.",
    "Configure the logging level to DEBUG for troubleshooting.",
    "Pin the dependency versions in requirements.txt.",
    "Restart the service after updating the configuration.",
    "Create a new branch from main for the hotfix.",
    "Back up the database before running the schema migration.",
    "Check the error logs for any timeout exceptions.",
    "Enable the feature flag for the beta users group.",
]

BENIGN_SQL_SAMPLES = [
    "SELECT u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100;",
    "INSERT INTO audit_log (event_type, user_id, timestamp) VALUES ('login', 42, NOW());",
    "UPDATE products SET price = price * 1.05 WHERE category = 'electronics' AND stock > 0;",
    "DELETE FROM sessions WHERE last_active < DATE_SUB(NOW(), INTERVAL 30 DAY);",
    "CREATE TABLE IF NOT EXISTS metrics (id SERIAL PRIMARY KEY, name VARCHAR(255), value DECIMAL(10,2));",
    "ALTER TABLE users ADD COLUMN last_login TIMESTAMP DEFAULT NULL;",
    "SELECT COUNT(*) as total, status FROM orders GROUP BY status HAVING COUNT(*) > 10;",
    "INSERT INTO notifications (user_id, message, read) SELECT id, 'Welcome!', false FROM users WHERE created_at > '2026-01-01';",
    "UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 789 AND quantity > 0;",
    "DELETE FROM temp_calculations WHERE created_at < CURRENT_DATE - INTERVAL '7 days';",
    "SELECT p.name, AVG(r.rating) as avg_rating FROM products p LEFT JOIN reviews r ON p.id = r.product_id GROUP BY p.id ORDER BY avg_rating DESC LIMIT 20;",
    "CREATE INDEX idx_users_email ON users (email) WHERE deleted_at IS NULL;",
]

BENIGN_ENV_SAMPLES = [
    "Copy .env.example to .env and fill in your database credentials.",
    "The .env file should contain DATABASE_URL, REDIS_URL, and SECRET_KEY.",
    "Make sure to add your .env file to .gitignore to avoid committing secrets.",
    "Set FLASK_ENV=development in your .env for local debugging.",
    "The API requires STRIPE_SECRET_KEY in your .env file. Get it from the Stripe dashboard.",
    "Run cp .env.example .env and then edit the file to configure your local environment.",
    "Environment variables are loaded from .env using python-dotenv.",
    "If the .env file is missing, the app falls back to system environment variables.",
]

BENIGN_LONG_DOCS = [
    """## Getting Started

To set up the development environment, you'll need Python 3.10 or later and Node.js 18+.

1. Clone the repository: git clone https://github.com/example/project.git
2. Install Python dependencies: pip install -e ".[dev]"
3. Install frontend dependencies: cd frontend && npm install
4. Copy the example config: cp config.example.yaml config.yaml
5. Run the database migrations: python manage.py migrate
6. Start the development server: python manage.py runserver

The API will be available at http://localhost:8000/api/v1/. The frontend dev server runs on port 3000 with hot reloading enabled. See the Architecture section below for an overview of how the components interact.""",

    """## Architecture

The application follows a standard three-tier architecture:

API Layer: Django REST Framework handles HTTP requests, authentication, and serialization. All endpoints are versioned under /api/v1/. Rate limiting is configured per-user with django-ratelimit.

Business Logic: Service classes in core/services/ contain domain logic. They are framework-agnostic and can be tested without HTTP overhead. Each service handles one aggregate root.

Data Layer: PostgreSQL with Django ORM. Migrations are auto-generated but manually reviewed before committing. We use select_related and prefetch_related aggressively to avoid N+1 queries.

Background Tasks: Celery with Redis as the broker. Long-running operations (report generation, email sending, data exports) run asynchronously. Results are stored for 24 hours.""",

    """## Contributing

We welcome contributions! Here's how to get started:

1. Fork the repository and create a feature branch from main
2. Write tests for any new functionality (we require >90% coverage for new code)
3. Run the full test suite: pytest --cov=src tests/
4. Run the linter: ruff check src/ tests/
5. Run type checking: mypy src/
6. Submit a pull request with a clear description of the changes

Please follow conventional commits for your commit messages (feat:, fix:, docs:, etc.). The CI pipeline runs all checks automatically. PRs with failing checks won't be reviewed.

For larger changes, please open an issue first to discuss the approach. This helps avoid duplicate work and ensures your contribution aligns with the project roadmap.""",

    """## Configuration Reference

All configuration is done through environment variables or a YAML config file. Environment variables take precedence over config file values.

DATABASE_URL: Database connection string. Default: sqlite:///db.sqlite3
REDIS_URL: Redis connection for caching and Celery. Default: redis://localhost:6379/0
SECRET_KEY: Django secret key for cryptographic signing. Required, no default.
DEBUG: Enable debug mode. Default: false. Never use in production.
LOG_LEVEL: Logging verbosity (DEBUG, INFO, WARNING, ERROR). Default: INFO
ALLOWED_HOSTS: Comma-separated list of allowed hostnames. Default: localhost
CORS_ORIGINS: Allowed CORS origins. Default: http://localhost:3000
RATE_LIMIT: Default API rate limit per user. Default: 100/hour

For production deployments, see the deployment guide in docs/deployment.md.""",

    """## Troubleshooting

Problem: Tests fail with connection refused errors.
The test suite requires a running PostgreSQL instance. Make sure your DATABASE_URL points to a valid database. For CI, we use a Docker container defined in the GitHub Actions workflow.

Problem: Import errors after pulling new changes.
Run pip install -e ".[dev]" to ensure new dependencies are installed. If you see Module not found for a newly added package, this is almost always the cause.

Problem: Celery tasks not executing.
Check that Redis is running and REDIS_URL is correct. You can test connectivity with redis-cli ping. Also ensure the Celery worker is running with: celery -A project worker --loglevel=info.

Problem: Slow API responses.
Enable Django Debug Toolbar (DEBUG=true) and check for N+1 query patterns. Most performance issues are database-related. The silk profiler is also available at /silk/ when debug mode is enabled.""",

    """MIT License

Copyright (c) 2026 Example Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the Software), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.""",

    """## API Reference

Authentication: All API endpoints require a Bearer token in the Authorization header. Tokens are obtained via the /api/v1/auth/login endpoint with email and password. Tokens expire after 24 hours. Use the /api/v1/auth/refresh endpoint to get a new token before expiry.

GET /api/v1/users: List all users (admin only). Supports pagination with page and per_page query parameters. Returns JSON array of user objects.

POST /api/v1/users: Create a new user. Requires email, name, and role in the request body. Returns the created user object with a 201 status code.

GET /api/v1/users/:id: Get a specific user by ID. Returns 404 if not found.

PATCH /api/v1/users/:id: Update user fields. Only provided fields are updated. Returns the updated user object.

DELETE /api/v1/users/:id: Soft-delete a user. Sets deleted_at timestamp. Returns 204 No Content.""",
]

BENIGN_CODE_COMMENTS = [
    "# TODO: Refactor this to use the new database connection pool",
    "// FIXME: Race condition when multiple threads access the cache simultaneously",
    "# NOTE: This function assumes the input has already been validated by the middleware",
    "// HACK: Temporary workaround for the timezone conversion bug in the third-party library",
    "# WARNING: Do not change the order of these operations. They must run sequentially",
    "// Performance: This query was optimized from 3.2s to 45ms by adding the composite index",
    "# Security: Input is sanitized by the framework before reaching this handler",
    "// Deprecated: Use the new UserService.findById() method instead",
]


def main():
    records = load_dataset(DATASET_PATH)
    original_count = len(records)
    original_mal = sum(1 for r in records if r["label"] == 1)
    original_ben = sum(1 for r in records if r["label"] == 0)

    removed = []
    kept = []

    for i, rec in enumerate(records):
        text = rec["text"]
        label = rec["label"]

        if label == 1:
            if is_benign_heading(text):
                removed.append((i, text, "benign_heading"))
                continue
            if is_benign_commit_message(text):
                removed.append((i, text, "benign_commit_message"))
                continue
            if is_benign_bold_reference(text):
                removed.append((i, text, "benign_bold_reference"))
                continue
            if is_benign_code_construct(text):
                removed.append((i, text, "benign_code_construct"))
                continue
            if is_benign_yaml_fragment(text):
                removed.append((i, text, "benign_yaml_fragment"))
                continue
            if is_fragment_without_attack_semantics(text):
                removed.append((i, text, "fragment_no_attack"))
                continue

        kept.append(rec)

    # Add new benign samples
    added = []
    for text in BENIGN_IMPERATIVE_INSTRUCTIONS:
        kept.append({"text": text, "label": 0})
        added.append(("imperative_instruction", text[:60]))

    for text in BENIGN_SQL_SAMPLES:
        kept.append({"text": text, "label": 0})
        added.append(("sql_sample", text[:60]))

    for text in BENIGN_ENV_SAMPLES:
        kept.append({"text": text, "label": 0})
        added.append(("env_sample", text[:60]))

    for text in BENIGN_LONG_DOCS:
        kept.append({"text": text, "label": 0})
        added.append(("long_doc", text[:60]))

    for text in BENIGN_CODE_COMMENTS:
        kept.append({"text": text, "label": 0})
        added.append(("code_comment", text[:60]))

    # Write cleaned dataset
    with open(DATASET_PATH, "w") as f:
        for rec in kept:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Write audit log
    new_mal = sum(1 for r in kept if r["label"] == 1)
    new_ben = sum(1 for r in kept if r["label"] == 0)

    with open(AUDIT_LOG, "w") as f:
        f.write("=== Dataset Cleanup Audit ===\n\n")
        f.write(f"Original: {original_count} ({original_mal} mal, {original_ben} ben)\n")
        f.write(f"Cleaned:  {len(kept)} ({new_mal} mal, {new_ben} ben)\n")
        f.write(f"Removed:  {len(removed)} mislabeled malicious samples\n")
        f.write(f"Added:    {len(added)} new benign samples\n\n")

        f.write("--- Removed samples ---\n")
        for idx, text, reason in removed:
            f.write(f"  [{reason}] line {idx}: {text[:80]!r}\n")

        f.write(f"\n--- Added benign samples ({len(added)}) ---\n")
        for category, preview in added:
            f.write(f"  [{category}] {preview!r}\n")

    print(f"Original: {original_count} ({original_mal} mal, {original_ben} ben)")
    print(f"Removed:  {len(removed)} mislabeled malicious samples")
    print(f"Added:    {len(added)} new benign samples")
    print(f"Cleaned:  {len(kept)} ({new_mal} mal, {new_ben} ben)")
    print(f"\nAudit log: {AUDIT_LOG}")

    reasons = {}
    for _, _, reason in removed:
        reasons[reason] = reasons.get(reason, 0) + 1
    print("\nRemoval breakdown:")
    for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"  {reason}: {count}")


if __name__ == "__main__":
    main()
