# oauth2 Documentation

## Overview

OAuth2 authentication and authorization service built with Python 3.13, Typer, and FastAPI.

## Installation

### Prerequisites

- Python 3.13 or later
- uv package manager

### Development Setup

```bash
# Clone the repository
git clone <repository-url>
cd oauth2

# Install dependencies
make sync

# Run tests
make test

# Run the application
make run
```

## Architecture

### Project Structure

```
oauth2/
├── src/
│   ├── cli.py              # CLI entry point
│   ├── logging_config.py   # Logging configuration
│   └── services/           # Business logic services
├── tests/                  # Test suite
├── specs/                  # Specifications and backlog
└── docs/                   # User documentation
```

## Usage

### Basic Commands

```bash
# Show help
make run ARGS='--help'

# Run hello command
make run ARGS='hello'
make run ARGS='hello --name Alice'
```

## Development

### Code Quality

```bash
# Run all checks
make check

# Format code
make format

# Run linter
make lint

# Run type checker
make typecheck
```

### Testing

```bash
# Run tests
make test

# Run with coverage
make test-cov
```

### Docker

```bash
# Build image
make docker-build

# Run with Docker Compose
make run-up

# Stop services
make run-down
```

## Contributing

1. Create a feature branch
2. Make your changes
3. Run `make check` to ensure all tests pass
4. Commit and push your changes
5. Create a pull request

## License

MIT License - see LICENSE file for details.
