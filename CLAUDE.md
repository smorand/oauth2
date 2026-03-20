# oauth2 - AI Documentation

## Overview

OAuth2 authentication and authorization service.

**Tech Stack:** Python 3.13, Typer, Ruff, mypy, pytest

## Key Commands

```bash
make sync               # Install dependencies
make run                # Run the application
make run ARGS='--help'  # Run with arguments
make check              # Run all quality checks (lint, format, typecheck, test)
make docker-build       # Build Docker image
```

## Project Structure

- `src/cli.py` - CLI entry point (Typer app)
- `tests/` - Test suite with conftest.py

## Conventions

- Entry point in `src/cli.py` contains only CLI wiring
- Business logic in separate modules within `src/`
- Use `@dataclass(frozen=True)` for value objects
- All async operations use asyncio patterns
- Logging with `%` formatting, not f-strings

## Documentation Index

- `.agent_docs/python.md` - Python coding standards and conventions
- `.agent_docs/makefile.md` - Detailed Makefile documentation

## Git Workflow

- Every modification must be committed and pushed if a remote repo exists
- Every modification includes docs updates (CLAUDE.md + .agent_docs and README.md + docs)
