# oauth2

OAuth2 authentication and authorization service.

## Project Structure

```
oauth2/
├── src/
│   ├── cli.py             # CLI entry point (Typer)
│   └── logging_config.py  # Logging setup
├── tests/                 # Test suite
├── pyproject.toml         # Project configuration
├── Makefile               # Build automation
├── Dockerfile             # Container build
└── README.md              # This file
```

## Requirements

- Python 3.13 or later
- uv (package manager)

## Quick Start

```bash
# Install dependencies
make sync

# Run the application
make run

# Run with arguments
make run ARGS='--help'
```

## Available Commands

| Command | Description |
|---------|-------------|
| `make sync` | Install dependencies |
| `make run` | Run the application |
| `make run ARGS='...'` | Run with arguments |
| `make test` | Run tests |
| `make test-cov` | Run tests with coverage |
| `make check` | Run all quality checks |
| `make format` | Format code with Ruff |
| `make docker-build` | Build Docker image |
| `make run-up` | Start with Docker Compose |
| `make clean` | Remove build artifacts |
| `make help` | Show all available commands |
