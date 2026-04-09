# Contributing

CloneGuard is in active development and welcomes contributions.

## Getting Started

```bash
git clone https://github.com/prodnull/cloneguard.git
cd cloneguard
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev,mini]"
pytest
```

## Development Workflow

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run the test suite: `pytest`
5. Run the linter: `ruff check src/`
6. Run type checking: `mypy src/cloneguard/`
7. Submit a pull request

## What We Need

**Detection rules.** New patterns for attack techniques we don't cover.
Each rule needs at least one positive test (matches an attack) and one negative
test (does not match benign content). See existing rules in
`src/cloneguard/rules/` for the format.

**False positive reports.** If CloneGuard flags something that isn't an attack,
open an issue with the file content and detection output.

**Agent integrations.** We support Claude Code, Gemini CLI, and Cursor. Help
testing with Windsurf, VS Code Copilot, or other hook-capable agents is
valuable.

**Real-world testing.** Run CloneGuard on your repositories and report what
works and what doesn't.

## Code Standards

- Python 3.11+
- `ruff check` and `mypy --strict` must pass
- Tests required for new features
- Conventional Commits for commit messages: `type(scope): description`

## Reporting Security Issues

If you find a security vulnerability in CloneGuard, please report it via
[GitHub Security Advisories](https://github.com/prodnull/cloneguard/security/advisories)
rather than opening a public issue.
