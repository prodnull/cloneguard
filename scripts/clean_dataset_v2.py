#!/usr/bin/env python3
"""Dataset cleanup v2: fix remaining mislabels and add long benign samples.

Fixes identified by second audit (2026-03-09):
1. Remove clearly mislabeled malicious samples (code fragments, package entries, docstrings)
2. Add long benign samples (500-2000 chars) to fix length distribution shortcut
3. Add targeted hard negatives for known FP patterns
4. All new samples hand-written (no Ollama) for quality control

Writes cleaned dataset to data/training/dataset.jsonl (overwrites in place).
Writes audit log to data/training/cleanup-v2-audit.log.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "data" / "training" / "dataset.jsonl"
AUDIT_LOG = ROOT / "data" / "training" / "cleanup-v2-audit.log"


def load_dataset(path: Path) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# Mislabel detection rules (conservative — only remove clearly benign)
# ---------------------------------------------------------------------------

_ATTACK_WORDS_BASIC = [
    "curl", "wget", "inject", "exfil", "override", "bypass",
    "steal", "hack", "shell", "command", "base64", "encode",
    "decode", "http://", "https://",
]

_ATTACK_WORDS_EXTENDED = _ATTACK_WORDS_BASIC + [
    "credential", "password", "exploit", "backdoor", "malicious",
    "ignore", "disregard", "system(", "admin", "root",
]


def _has_attack_words(text: str, words: list[str] | None = None) -> bool:
    lower = text.lower()
    return any(w in lower for w in (words or _ATTACK_WORDS_BASIC))


def is_python_self_attr(text: str) -> bool:
    """Python self.x = y assignments with no attack semantics."""
    text = text.strip()
    return (
        bool(re.match(r"^self\.\w+\s*=", text))
        and len(text) <= 60
        and not _has_attack_words(text)
    )


def is_heading_label_only(text: str) -> bool:
    """All-caps labels ending with colon, no attack content."""
    text = text.strip()
    return (
        bool(re.match(r"^[A-Z][A-Z\s]+:$", text))
        and len(text) <= 40
        and not _has_attack_words(text, [
            "inject", "exfil", "hack", "steal", "exploit",
            "override", "bypass", "credential", "password",
        ])
    )


def is_benign_package_entry(text: str) -> bool:
    """Package lock version entries and standard npm scripts."""
    text = text.strip()
    if len(text) > 80:
        return False

    # Package lock version entries: "name@^ver": "version \"x.y.z\""
    if re.match(r'^"[\w@^~.<>=-]+"\s*:\s*"version\s', text):
        return True

    # Simple dep entries: "lodash": "^4.17.21"
    if re.match(r'^"[\w-]+"\s*:\s*"\^?\d+\.\d+', text):
        return True

    # Standard trivial JSON values
    if text in ('"status": "ok"', '"status": "error"', '"version": "1.0.0"'):
        return True

    # Standard npm scripts with no suspicious content
    if re.match(
        r'^"(start|test|build|lint|format)"\s*:\s*"(node|npm|npx|tsc|jest|eslint|prettier)\s',
        text,
    ):
        if not _has_attack_words(text, [
            "curl", "wget", "http://", "https://",
            "credential", "secret", "token", "password",
        ]):
            return True

    # IDE settings that are normal
    if re.match(r'^"terminal\.integrated\.shell\.\w+"\s*:\s*"/bin/', text):
        return True

    # Docker config paths (no URLs)
    if re.match(r'^"dockerFile"\s*:\s*"', text):
        if not _has_attack_words(text, ["curl", "wget", "http://", "https://"]):
            return True

    return False


def is_variable_decl(text: str) -> bool:
    """Bare 'variable: name' declarations from Ollama training."""
    return bool(re.match(r"^variable:\s*\w+$", text.strip(), re.IGNORECASE))


def is_backtick_single_ident(text: str) -> bool:
    """Backtick-wrapped single identifiers like `escalateToRoot`."""
    return bool(re.match(r"^`\w+`$", text.strip()))


def is_benign_docstring(text: str) -> bool:
    """Short Python docstrings with no attack semantics."""
    text = text.strip()
    return (
        bool(re.match(r'^""".*"""$', text))
        and len(text) <= 60
        and not _has_attack_words(text, [
            "inject", "exfil", "hack", "steal", "override", "bypass",
            "credential", "curl", "wget", "shell", "command", "ignore",
            "disregard",
        ])
    )


def is_benign_conditional(text: str) -> bool:
    """Simple if-conditions that are just code."""
    text = text.strip()
    return (
        bool(re.match(r"^if\s+[\w.]+\s*[><=!]", text))
        and len(text) <= 60
        and not _has_attack_words(text, _ATTACK_WORDS_EXTENDED)
    )


def is_benign_func_sig(text: str) -> bool:
    """Standard function signatures without attack context."""
    text = text.strip()
    if len(text) > 80:
        return False
    if not any(re.match(p, text) for p in [r"^fn \w+\(", r"^func \w+\(", r"^def \w+\("]):
        return False
    return not _has_attack_words(text, _ATTACK_WORDS_EXTENDED)


# ---------------------------------------------------------------------------
# New benign samples — all hand-written for quality
# ---------------------------------------------------------------------------

# Loaded from separate data section at the bottom of this file to keep
# the logic section readable. See LONG_BENIGN_* and HARD_NEGATIVE_* below.

def _load_long_benign_samples() -> list[tuple[str, str]]:
    """Return (text, category) pairs for all new benign samples."""
    samples = []
    for text in LONG_BENIGN_READMES:
        samples.append((text, "long_readme"))
    for text in LONG_BENIGN_CODE:
        samples.append((text, "long_code"))
    for text in LONG_BENIGN_CONFIG:
        samples.append((text, "long_config"))
    for text in LONG_BENIGN_SECURITY_DOCS:
        samples.append((text, "long_security_doc"))
    for text in HARD_NEGATIVE_SQL:
        samples.append((text, "hard_neg_sql"))
    for text in HARD_NEGATIVE_DEPLOYMENT:
        samples.append((text, "hard_neg_deploy"))
    for text in HARD_NEGATIVE_SECURITY_REVIEW:
        samples.append((text, "hard_neg_sec_review"))
    for text in HARD_NEGATIVE_GIT_HOOKS:
        samples.append((text, "hard_neg_git_hooks"))
    for text in HARD_NEGATIVE_IMPERATIVE_LONG:
        samples.append((text, "hard_neg_imperative"))
    return samples


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    records = load_dataset(DATASET_PATH)
    original_count = len(records)
    original_mal = sum(1 for r in records if r["label"] == 1)
    original_ben = sum(1 for r in records if r["label"] == 0)

    removed: list[tuple[int, str, str]] = []
    kept: list[dict] = []

    checkers = [
        (is_python_self_attr, "python_self_attr"),
        (is_heading_label_only, "heading_label"),
        (is_benign_package_entry, "package_entry"),
        (is_variable_decl, "variable_decl"),
        (is_backtick_single_ident, "backtick_ident"),
        (is_benign_docstring, "docstring"),
        (is_benign_conditional, "code_conditional"),
        (is_benign_func_sig, "func_signature"),
    ]

    for i, rec in enumerate(records):
        text = rec["text"]
        label = rec["label"]

        if label == 1:
            was_removed = False
            for checker, reason in checkers:
                if checker(text):
                    removed.append((i, text, reason))
                    was_removed = True
                    break
            if was_removed:
                continue

        kept.append(rec)

    # Add new benign samples
    added: list[tuple[str, int]] = []
    for text, category in _load_long_benign_samples():
        kept.append({"text": text, "label": 0})
        added.append((category, len(text)))

    # Write cleaned dataset
    with open(DATASET_PATH, "w") as f:
        for rec in kept:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Compute stats
    new_mal = sum(1 for r in kept if r["label"] == 1)
    new_ben = sum(1 for r in kept if r["label"] == 0)

    # Write audit log
    with open(AUDIT_LOG, "w") as f:
        f.write("=== Dataset Cleanup V2 Audit ===\n\n")
        f.write(f"Original: {original_count} ({original_mal} mal, {original_ben} ben)\n")
        f.write(f"Cleaned:  {len(kept)} ({new_mal} mal, {new_ben} ben)\n")
        f.write(f"Removed:  {len(removed)} mislabeled malicious samples\n")
        f.write(f"Added:    {len(added)} new benign samples\n\n")

        f.write("--- Removed samples ---\n")
        reasons: dict[str, int] = {}
        for idx, text, reason in removed:
            reasons[reason] = reasons.get(reason, 0) + 1
            f.write(f"  [{reason}] line {idx}: {text[:80]!r}\n")

        f.write("\n--- Removal breakdown ---\n")
        for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
            f.write(f"  {reason}: {count}\n")

        f.write(f"\n--- Added benign samples ({len(added)}) ---\n")
        categories: dict[str, int] = {}
        for category, length in added:
            categories[category] = categories.get(category, 0) + 1
            f.write(f"  [{category}] {length} chars\n")

        f.write("\n--- Addition breakdown ---\n")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            f.write(f"  {cat}: {count}\n")

    print(f"Original: {original_count} ({original_mal} mal, {original_ben} ben)")
    print(f"Removed:  {len(removed)} mislabeled malicious samples")
    print(f"Added:    {len(added)} new benign samples")
    print(f"Cleaned:  {len(kept)} ({new_mal} mal, {new_ben} ben)")
    print(f"Balance:  {100 * new_mal / len(kept):.1f}% mal / {100 * new_ben / len(kept):.1f}% ben")

    print("\nRemoval breakdown:")
    for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"  {reason}: {count}")

    print("\nAddition breakdown:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    print(f"\nAudit log: {AUDIT_LOG}")


# ===========================================================================
# DATA SECTION: Hand-written benign samples
# ===========================================================================

LONG_BENIGN_READMES = [
    "## Installation\n\n### Prerequisites\n\n- Python 3.11 or later\n- PostgreSQL 15+\n- Redis 7+\n- Node.js 20+ (for the admin dashboard)\n\n### Quick Start\n\n```bash\ngit clone https://github.com/acme/widget-api.git\ncd widget-api\npython -m venv .venv\nsource .venv/bin/activate\npip install -e \".[dev]\"\n```\n\nCopy the environment template and edit it with your local database credentials:\n\n```bash\ncp .env.example .env\n# Edit .env with your DATABASE_URL, REDIS_URL, and SECRET_KEY\n```\n\nRun the database migrations:\n\n```bash\npython manage.py migrate\npython manage.py createsuperuser\n```\n\nStart the development server:\n\n```bash\npython manage.py runserver\n```\n\nThe API will be available at http://localhost:8000/api/v1/. The admin dashboard runs at http://localhost:8000/admin/.",

    "## Architecture Overview\n\nThe service follows a hexagonal architecture pattern with clear boundaries between domain logic and infrastructure concerns.\n\n### Core Components\n\n**Domain Layer** (`src/domain/`): Pure business logic with no framework dependencies. Domain entities, value objects, and repository interfaces live here.\n\n**Application Layer** (`src/application/`): Use cases that orchestrate domain operations. Each use case class handles exactly one business operation.\n\n**Infrastructure Layer** (`src/infrastructure/`): Concrete implementations of repository interfaces, database adapters, message queue clients, and external API integrations.\n\n**API Layer** (`src/api/`): HTTP request handlers, serializers, and middleware. Translates between HTTP and application use cases.\n\n### Data Flow\n\n1. HTTP request arrives at the API layer\n2. Request is validated and deserialized\n3. Application use case is invoked with domain-level parameters\n4. Use case orchestrates domain entities via repository interfaces\n5. Infrastructure layer handles persistence and side effects\n6. Response is serialized and returned\n\n### Testing Strategy\n\nEach layer has its own test suite. Domain tests are pure unit tests with no mocking. Application tests mock repository interfaces. Infrastructure tests use testcontainers for real database instances.",

    "## Contributing\n\nWe welcome contributions from the community.\n\n### Development Setup\n\n1. Fork the repository and clone your fork\n2. Create a virtual environment: `python -m venv .venv`\n3. Install development dependencies: `pip install -e \".[dev]\"`\n4. Install pre-commit hooks: `pre-commit install`\n5. Create a feature branch: `git checkout -b feature/your-feature`\n\n### Code Standards\n\n- All code must pass `ruff check` and `ruff format`\n- Type annotations are required for all public functions\n- Minimum test coverage for new code: 90%\n- Docstrings follow Google style\n- Commit messages follow Conventional Commits\n\n### Pull Request Process\n\n1. Ensure all tests pass: `pytest --cov=src tests/`\n2. Run the full lint suite: `ruff check src/ tests/ && mypy src/`\n3. Update documentation if you changed public APIs\n4. Add a changelog entry under the Unreleased section\n5. Request review from at least one maintainer",

    "## Deployment Guide\n\n### Production Requirements\n\n- Linux (Ubuntu 22.04 LTS recommended)\n- 4 CPU cores, 8 GB RAM minimum\n- PostgreSQL 15+ with 50 GB storage\n- Redis 7+ for caching and task queue\n- NGINX or Caddy as reverse proxy\n- TLS certificate (Let's Encrypt recommended)\n\n### Environment Variables\n\n| Variable | Required | Default | Description |\n|----------|----------|---------|-------------|\n| DATABASE_URL | Yes | - | PostgreSQL connection string |\n| REDIS_URL | Yes | - | Redis connection string |\n| SECRET_KEY | Yes | - | Django secret key for signing |\n| ALLOWED_HOSTS | Yes | - | Comma-separated hostnames |\n| DEBUG | No | false | Enable debug mode |\n| LOG_LEVEL | No | INFO | Logging verbosity |\n\n### Deployment Steps\n\n1. Clone the repository on the production server\n2. Create a Python virtual environment and install dependencies\n3. Set all required environment variables\n4. Run database migrations\n5. Collect static files\n6. Configure systemd services for gunicorn and celery workers\n7. Configure NGINX to proxy to gunicorn\n8. Enable and start all services",

    "## API Reference\n\n### Authentication\n\nAll API endpoints except `/api/v1/auth/login` require a Bearer token in the Authorization header. Tokens are obtained via POST to `/api/v1/auth/login` with email and password. Tokens expire after 24 hours.\n\n### Endpoints\n\n#### Users\n\n- `GET /api/v1/users/` list all users (admin only). Supports pagination.\n- `POST /api/v1/users/` create a new user. Required: email, name, role.\n- `GET /api/v1/users/:id` get user by ID.\n- `PATCH /api/v1/users/:id` update user fields.\n- `DELETE /api/v1/users/:id` soft-delete a user.\n\n#### Projects\n\n- `GET /api/v1/projects/` list projects for the authenticated user.\n- `POST /api/v1/projects/` create a new project.\n- `GET /api/v1/projects/:id` get project details.\n- `PUT /api/v1/projects/:id` update project settings.\n- `DELETE /api/v1/projects/:id` archive a project.\n\n### Error Responses\n\nAll errors follow RFC 7807 Problem Details format.\n\n### Rate Limiting\n\nStandard users: 100 requests per minute. Admin users: 500 per minute. Rate limit headers are included in every response.",

    "## Troubleshooting\n\n### Common Issues\n\n**Problem: Application fails to start with connection refused error**\n\nThe application cannot connect to PostgreSQL. Check that:\n1. PostgreSQL is running: `systemctl status postgresql`\n2. The DATABASE_URL environment variable is set correctly\n3. The database exists\n4. The user has permissions\n\n**Problem: Celery workers not processing tasks**\n\nCheck the Redis connection and worker status:\n1. Verify Redis is running: `redis-cli ping` should return PONG\n2. Check REDIS_URL is set correctly\n3. Inspect the worker logs\n4. Verify tasks are being queued\n\n**Problem: Slow API responses over 500ms**\n\nMost performance issues are database-related:\n1. Enable the Django Debug Toolbar\n2. Check for N+1 queries\n3. Verify indexes exist on frequently-queried columns\n4. Check PostgreSQL slow query log\n\n**Problem: Tests fail in CI but pass locally**\n\nUsually caused by: different Python version, missing env vars, fresh database state, or timezone differences.",

    "## Changelog\n\n### v2.4.0 (2026-03-01)\n\n#### Added\n- WebSocket support for real-time notifications\n- Bulk import endpoint for CSV data files\n- Rate limiting per API key with configurable thresholds\n- Health check endpoint for load balancer integration\n- OpenTelemetry tracing for distributed request tracking\n\n#### Changed\n- Upgraded Django from 5.0 to 5.1\n- Migrated from django-rest-framework to Django Ninja\n- Improved query performance for project listing (3.2s to 45ms)\n- Updated all dependencies to latest versions\n\n#### Fixed\n- Race condition in concurrent order processing\n- Memory leak in WebSocket connection handler\n- Incorrect pagination count when filters are applied\n- Timezone handling for non-UTC timezones\n\n#### Security\n- Updated cryptography package to 42.0.0\n- Added CSRF protection to all state-changing endpoints\n- Implemented request signing for webhook deliveries\n\n### v2.3.1 (2026-02-15)\n\n#### Fixed\n- Database migration failure on PostgreSQL 14\n- Email template rendering for password reset flow",

    "## Database Schema\n\n### Users Table\n\n```sql\nCREATE TABLE users (\n    id SERIAL PRIMARY KEY,\n    email VARCHAR(255) UNIQUE NOT NULL,\n    name VARCHAR(255) NOT NULL,\n    password_hash VARCHAR(255) NOT NULL,\n    role VARCHAR(50) DEFAULT 'user',\n    is_active BOOLEAN DEFAULT true,\n    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),\n    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),\n    deleted_at TIMESTAMP WITH TIME ZONE\n);\n\nCREATE INDEX idx_users_email ON users (email) WHERE deleted_at IS NULL;\n```\n\n### Projects Table\n\n```sql\nCREATE TABLE projects (\n    id SERIAL PRIMARY KEY,\n    name VARCHAR(255) NOT NULL,\n    description TEXT,\n    owner_id INTEGER REFERENCES users(id),\n    visibility VARCHAR(20) DEFAULT 'private',\n    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),\n    archived_at TIMESTAMP WITH TIME ZONE\n);\n\nCREATE INDEX idx_projects_owner ON projects (owner_id) WHERE archived_at IS NULL;\n```\n\n### Migration Strategy\n\nWe use Alembic for database migrations. All migrations are auto-generated but manually reviewed before committing.",
]

LONG_BENIGN_CODE = [
    'import logging\nfrom dataclasses import dataclass, field\nfrom datetime import datetime, timezone\nfrom typing import Optional\n\nlogger = logging.getLogger(__name__)\n\n\n@dataclass\nclass UserProfile:\n    """Represents a user profile in the system."""\n\n    user_id: int\n    email: str\n    display_name: str\n    bio: Optional[str] = None\n    avatar_url: Optional[str] = None\n    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))\n    last_login: Optional[datetime] = None\n    preferences: dict = field(default_factory=dict)\n\n    def update_login_timestamp(self) -> None:\n        self.last_login = datetime.now(timezone.utc)\n        logger.info("Updated login timestamp for user %d", self.user_id)\n\n    def set_preference(self, key: str, value: str) -> None:\n        self.preferences[key] = value\n\n    def get_preference(self, key: str, default: str = "") -> str:\n        return self.preferences.get(key, default)\n\n    @property\n    def is_profile_complete(self) -> bool:\n        return bool(self.display_name and self.email and self.bio)',

    'use std::collections::HashMap;\nuse std::sync::Arc;\nuse tokio::sync::RwLock;\n\npub struct Cache<V: Clone + Send + Sync> {\n    store: Arc<RwLock<HashMap<String, CacheEntry<V>>>>,\n    default_ttl: std::time::Duration,\n}\n\nstruct CacheEntry<V> {\n    value: V,\n    expires_at: std::time::Instant,\n}\n\nimpl<V: Clone + Send + Sync> Cache<V> {\n    pub fn new(default_ttl: std::time::Duration) -> Self {\n        Self {\n            store: Arc::new(RwLock::new(HashMap::new())),\n            default_ttl,\n        }\n    }\n\n    pub async fn get(&self, key: &str) -> Option<V> {\n        let store = self.store.read().await;\n        store.get(key).and_then(|entry| {\n            if entry.expires_at > std::time::Instant::now() {\n                Some(entry.value.clone())\n            } else {\n                None\n            }\n        })\n    }\n\n    pub async fn set(&self, key: impl Into<String>, value: V) {\n        let mut store = self.store.write().await;\n        store.insert(\n            key.into(),\n            CacheEntry {\n                value,\n                expires_at: std::time::Instant::now() + self.default_ttl,\n            },\n        );\n    }\n\n    pub async fn evict_expired(&self) -> usize {\n        let mut store = self.store.write().await;\n        let now = std::time::Instant::now();\n        let before = store.len();\n        store.retain(|_, entry| entry.expires_at > now);\n        before - store.len()\n    }\n}',

    "import { describe, it, expect, beforeEach, afterEach } from 'vitest';\nimport { createApp } from '../src/app';\nimport { setupDatabase, teardownDatabase } from './helpers/db';\n\ndescribe('User API', () => {\n  let app;\n  let db;\n\n  beforeEach(async () => {\n    db = await setupDatabase();\n    app = createApp({ database: db });\n  });\n\n  afterEach(async () => {\n    await teardownDatabase(db);\n  });\n\n  describe('GET /api/users', () => {\n    it('returns an empty list when no users exist', async () => {\n      const response = await app.inject({\n        method: 'GET',\n        url: '/api/users',\n        headers: { authorization: 'Bearer test-admin-token' },\n      });\n\n      expect(response.statusCode).toBe(200);\n      expect(response.json()).toEqual({ data: [], total: 0, page: 1 });\n    });\n\n    it('returns paginated results', async () => {\n      for (let i = 0; i < 25; i++) {\n        await db.query(\n          'INSERT INTO users (email, name) VALUES ($1, $2)',\n          [`user${i}@example.com`, `User ${i}`]\n        );\n      }\n\n      const response = await app.inject({\n        method: 'GET',\n        url: '/api/users?page=2&per_page=10',\n        headers: { authorization: 'Bearer test-admin-token' },\n      });\n\n      expect(response.statusCode).toBe(200);\n      const body = response.json();\n      expect(body.data).toHaveLength(10);\n      expect(body.total).toBe(25);\n    });\n  });\n});",

    "# CI/CD Pipeline Configuration\nname: CI/CD Pipeline\n\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n\njobs:\n  lint:\n    name: Lint and Type Check\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n      - run: pip install ruff mypy\n      - run: ruff check src/ tests/\n      - run: mypy src/\n\n  test:\n    name: Test Suite\n    runs-on: ubuntu-latest\n    needs: lint\n    services:\n      postgres:\n        image: postgres:16\n        env:\n          POSTGRES_DB: testdb\n          POSTGRES_USER: testuser\n          POSTGRES_PASSWORD: testpass\n        ports:\n          - 5432:5432\n      redis:\n        image: redis:7\n        ports:\n          - 6379:6379\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n          cache: pip\n      - run: pip install -e '.[dev]'\n      - run: pytest --cov=src --cov-report=xml tests/\n        env:\n          DATABASE_URL: postgresql://testuser:testpass@localhost:5432/testdb\n          REDIS_URL: redis://localhost:6379/0",
]

LONG_BENIGN_CONFIG = [
    "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"widget-api\"\nversion = \"2.4.0\"\ndescription = \"REST API for widget management\"\nreadme = \"README.md\"\nlicense = \"MIT\"\nrequires-python = \">=3.11\"\ndependencies = [\n    \"django>=5.1,<6.0\",\n    \"django-ninja>=1.3\",\n    \"psycopg[binary]>=3.2\",\n    \"redis>=5.0\",\n    \"celery>=5.4\",\n    \"gunicorn>=22.0\",\n    \"pydantic>=2.7\",\n    \"httpx>=0.27\",\n]\n\n[project.optional-dependencies]\ndev = [\n    \"pytest>=8.2\",\n    \"pytest-cov>=5.0\",\n    \"ruff>=0.5\",\n    \"mypy>=1.10\",\n]\n\n[tool.ruff]\ntarget-version = \"py312\"\nline-length = 100\n\n[tool.ruff.lint]\nselect = [\"E\", \"F\", \"I\", \"N\", \"W\", \"UP\", \"B\", \"SIM\"]\n\n[tool.mypy]\npython_version = \"3.12\"\nstrict = true\n\n[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\naddopts = \"-ra --strict-markers --tb=short\"",

    ".PHONY: all clean test lint format build install dev\n\nPYTHON := python3\nVENV := .venv\nBIN := $(VENV)/bin\nSRC := src tests\n\nall: lint test build\n\n$(VENV):\n\t$(PYTHON) -m venv $(VENV)\n\t$(BIN)/pip install --upgrade pip setuptools wheel\n\ninstall: $(VENV)\n\t$(BIN)/pip install -e .\n\ndev: $(VENV)\n\t$(BIN)/pip install -e \".[dev]\"\n\t$(BIN)/pre-commit install\n\nlint:\n\t$(BIN)/ruff check $(SRC)\n\t$(BIN)/mypy src/\n\nformat:\n\t$(BIN)/ruff format $(SRC)\n\ntest:\n\t$(BIN)/pytest --cov=src --cov-report=term-missing tests/\n\nclean:\n\trm -rf build/ dist/ *.egg-info\n\trm -rf .pytest_cache .mypy_cache .ruff_cache\n\tfind . -type d -name __pycache__ -exec rm -rf {} +",
]

LONG_BENIGN_SECURITY_DOCS = [
    "## Security Considerations\n\n### Authentication\n\nThe API uses JWT tokens signed with RS256 using a 2048-bit key pair. The public key is available at `/.well-known/jwks.json`.\n\nToken lifecycle:\n- Access tokens expire after 15 minutes\n- Refresh tokens expire after 7 days\n- Refresh tokens are rotated on each use\n- Revoked tokens are tracked in Redis\n\n### Authorization\n\nRole-based access control with four roles:\n- **viewer**: Read-only access to assigned projects\n- **editor**: Read/write access to assigned projects\n- **admin**: Full access to all projects and user management\n- **owner**: Admin plus billing and organization settings\n\n### Data Protection\n\n- All PII encrypted at rest using AES-256-GCM\n- Database backups encrypted with AWS KMS\n- TLS 1.3 required for all connections\n- API keys hashed with bcrypt (cost factor 12)\n- Passwords hashed with Argon2id\n\n### Audit Logging\n\nAll state-changing operations logged with actor identity, action, resource, before/after values, and UTC timestamp. Logs are append-only, retained for 90 days, then archived for 7 years.",

    "## Security Testing Guide\n\n### Running Security Tests\n\n```bash\npytest tests/security/ -v\n```\n\n### What the Tests Cover\n\n**Authentication tests** verify: expired tokens rejected with 401, malformed tokens rejected, token refresh requires valid refresh token, revoked tokens cannot be used, rate limiting on login attempts.\n\n**Authorization tests** verify: each role only accesses permitted endpoints, users cannot access other users' resources, admin endpoints reject non-admin tokens, escalation attempts are logged.\n\n**Input validation tests** verify: SQL injection attempts sanitized, XSS payloads escaped, path traversal rejected, oversized bodies rejected before parsing.\n\n**Rate limiting tests** verify: exceeded limits get 429, rate limit headers present, independent per-user counters, limits reset after window.\n\n### Adding New Security Tests\n\nWhen adding endpoints, include tests for: authentication required (401 without token), authorization correct (403 for wrong role), input validation for all user fields, error responses that don't leak internals.",
]

HARD_NEGATIVE_SQL = [
    "GRANT SELECT, INSERT, UPDATE ON schema.users TO app_readonly;",
    "REVOKE ALL PRIVILEGES ON DATABASE production FROM temp_user;",
    "DROP TABLE IF EXISTS temp_migration_staging CASCADE;",
    "GRANT USAGE ON SCHEMA public TO web_application;",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA api GRANT SELECT ON TABLES TO readonly_role;",
    "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_old_users_email;",
    "GRANT ALL FUNCTIONS IN SCHEMA internal TO backend_service;",
    "CREATE ROLE reporting_user WITH LOGIN PASSWORD 'changeme' VALID UNTIL '2027-01-01';",
    "GRANT pg_read_all_stats TO monitoring_agent;",
]

HARD_NEGATIVE_DEPLOYMENT = [
    "export DATABASE_URL=postgresql://appuser:${DB_PASSWORD}@db.internal:5432/production",
    "export REDIS_URL=redis://default:${REDIS_PASSWORD}@cache.internal:6379/0",
    "export SECRET_KEY=$(openssl rand -hex 32)",
    "export SENTRY_DSN=https://abc123@o456.ingest.sentry.io/789",
    "export LOG_LEVEL=WARNING",
    "export ALLOWED_HOSTS=api.example.com,www.example.com",
    "export CELERY_BROKER_URL=amqp://worker:${RABBITMQ_PASSWORD}@mq.internal:5672/production",
    "export AWS_DEFAULT_REGION=us-east-1",
    "export CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com",
    "export GUNICORN_WORKERS=4",
    "export GUNICORN_BIND=0.0.0.0:8000",
    "export DJANGO_SETTINGS_MODULE=config.settings.production",
]

HARD_NEGATIVE_SECURITY_REVIEW = [
    "This endpoint accepts user input in the query string. Verify that the ORM parameterizes the WHERE clause to prevent SQL injection.",
    "The file upload handler should validate the Content-Type header and reject anything outside the allowed types.",
    "Check that the authentication middleware rejects tokens signed with the none algorithm to prevent JWT confusion attacks.",
    "The password reset flow should use a constant-time comparison to prevent timing attacks on the reset token.",
    "Ensure that error responses from the API do not include stack traces or internal paths in production mode.",
    "The rate limiter should use the authenticated user ID as the key, not the IP address, to prevent shared-network abuse.",
    "Verify that the CORS configuration does not include wildcard origins in production.",
    "The webhook delivery system should sign payloads with HMAC-SHA256 so recipients can verify authenticity.",
    "Check that the session cookie has Secure, HttpOnly, and SameSite=Strict attributes set.",
    "The file download endpoint should set Content-Disposition: attachment to prevent XSS via uploaded HTML files.",
    "Ensure the Content-Security-Policy header blocks inline scripts and limits allowed sources.",
    "The API should return 404 (not 403) for resources the user cannot access, to prevent enumeration attacks.",
]

HARD_NEGATIVE_GIT_HOOKS = [
    "To set up the pre-commit hook, run: npx husky install && npx husky add .husky/pre-commit 'npm run lint-staged'",
    "The pre-push hook runs the full test suite. If tests fail, the push is blocked. Override with --no-verify only if you understand the risk.",
    "Git hooks are stored in .husky/ and committed to the repository so all developers share the same quality gates.",
    "The commit-msg hook validates that commit messages follow the Conventional Commits specification using commitlint.",
    "To skip hooks temporarily during a rebase: use the appropriate git flags. Do not use --no-verify habitually.",
    "The post-merge hook automatically runs npm install when package-lock.json changes, keeping dependencies in sync.",
    "lefthook is configured in lefthook.yml to run ruff check and mypy on staged Python files before each commit.",
    "The prepare-commit-msg hook adds the branch name as a prefix to commit messages for traceability.",
]

HARD_NEGATIVE_IMPERATIVE_LONG = [
    "To configure the development environment, first install the required system dependencies. On Ubuntu, run apt-get install build-essential libpq-dev libffi-dev. On macOS, install them with brew install postgresql libffi. Then create a virtual environment, install the Python packages, and run the database migrations before starting the server.",
    "Before deploying to production, verify that all environment variables are set correctly. Check the database connection by running the health check endpoint. Ensure the TLS certificate is valid and not expiring within 30 days. Run the smoke test suite against the staging environment. If all checks pass, proceed with the blue-green deployment.",
    "After cloning the repository, initialize the git submodules with git submodule update --init --recursive. Install the project dependencies with npm install in the root directory and in the packages/frontend directory. Copy the environment template files and configure them for your local setup.",
    "To run the test suite locally, you need a PostgreSQL database and a Redis instance. The easiest way is to use Docker Compose with the test configuration file. This starts both services with the correct settings. Then run pytest with the test environment. The test database is created and destroyed automatically.",
    "When upgrading between major versions, follow the migration guide carefully. First, back up your database. Then update the package version in your requirements file. Check the changelog for breaking changes. Run the database migrations. Finally, restart all application processes and verify the health endpoints.",
]


if __name__ == "__main__":
    main()
