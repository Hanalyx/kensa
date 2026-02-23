# Contributing to Kensa

Thanks for your interest in contributing to Kensa! This guide covers everything you need to get started.

## Getting Started

```bash
git clone https://github.com/Hanalyx/kensa.git
cd kensa
pip install -e ".[dev]"
pre-commit install
```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Run the checks locally before pushing:

```bash
# Tests
pytest tests/ -v

# Lint and format
ruff check runner/ schema/ tests/
ruff format runner/ schema/ tests/

# Type check
mypy runner/ schema/ --ignore-missing-imports

# All pre-commit hooks
pre-commit run --all-files
```

4. Push your branch and open a PR against `main`
5. CI must pass before merging — `Lint & Type Check` and `Validate Rules` are required

## Code Style

- Python 3.10+ with `from __future__ import annotations`
- Ruff for linting and formatting (line-length 88, double quotes)
- Google-style docstrings
- mypy for type checking

## Rule Contributions

Rules live in `rules/<category>/<rule-id>.yml` and must pass schema validation (`schema/rule.schema.json`). Key conventions:

- Check blocks use `run:` (not `command:`) and `expected_exit:` (not `expected_exit_code:`)
- SSH checks should use `sshd_effective_config` (runs `sshd -T`), not `config_value` on the static file
- PAM rules should use `when: authselect` when authselect manages PAM
- See `CLAUDE.md` for the full list of field-name conventions

## Reporting Issues

Open an issue at https://github.com/Hanalyx/kensa/issues with:

- What you expected to happen
- What actually happened
- Steps to reproduce (rule ID, host OS, relevant config)

## License

By contributing, you agree that your contributions will be licensed under the same [Business Source License 1.1](https://github.com/Hanalyx/kensa/blob/main/LICENSE) that covers the project.
