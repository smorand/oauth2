# oauth2 : AI Documentation

## Overview

OAuth 2.1 compliant authorization server with OpenID Connect support. Supports authorization code flow (PKCE), client credentials, device authorization grant, token refresh with rotation and reuse detection, token introspection/revocation, social login (Google, GitHub), and SAML SP integration.

**Tech Stack:** Python 3.13, FastAPI, Typer, Pydantic Settings, PyJWT (RS256), Argon2id/bcrypt, Jinja2, OpenTelemetry, Ruff, mypy, pytest

## Key Commands

```bash
make sync               # Install dependencies
make run                # Run the OAuth2 server (default: http://localhost:8000)
make check              # Full quality gate (lint, format, typecheck, security, tests+coverage)
make test               # Run tests (297 tests)
make test-cov           # Run tests with coverage (>= 80%)
make docker-build       # Build Docker image
make run-up             # Start with Docker Compose
```

## Project Structure

```
src/
├── cli.py                  # Typer CLI (serve, generate-keys, create-admin)
├── config.py               # pydantic-settings Settings class
├── app.py                  # FastAPI application factory
├── dependencies.py         # DI container wiring all services
├── logging_config.py       # Rich + file logging setup
├── tracing.py              # OpenTelemetry JSONL tracing
├── models/                 # Frozen dataclass entities
│   ├── user.py, client.py, token.py, consent.py, scope.py, saml.py
│   └── schemas.py          # Pydantic request/response schemas
├── crypto/                 # Cryptographic operations
│   ├── keys.py             # RSA key management + JWKS
│   ├── jwt_handler.py      # JWT creation/validation (RS256)
│   ├── password.py         # Argon2id, bcrypt, SHA-256 token hashing
│   └── pkce.py             # PKCE S256 verification
├── storage/                # Pluggable storage backends
│   ├── base.py             # StorageBackend Protocol
│   └── json_backend.py     # JSON file storage implementation
├── services/               # Business logic layer
│   ├── user_service.py     # Registration, auth, lockout
│   ├── client_service.py   # Client CRUD, secret rotation
│   ├── token_service.py    # Token issuance, refresh rotation, introspect, revoke
│   ├── auth_code_service.py # Authorization code management
│   ├── consent_service.py  # Consent grants and revocation
│   ├── device_code_service.py # Device authorization grant
│   ├── scope_service.py    # Scope validation and management
│   ├── social_service.py   # Google OIDC + GitHub OAuth
│   ├── saml_service.py     # SAML SP integration
│   ├── audit_service.py    # Structured JSONL audit logging
│   └── bootstrap.py        # Admin user creation
├── routes/                 # HTTP endpoints
│   ├── oauth.py            # /oauth/* (authorize, token, introspect, revoke, device)
│   ├── auth.py             # /auth/* (register, consents)
│   ├── oidc.py             # /.well-known/*, /oidc/userinfo
│   ├── admin.py            # /admin/* (clients, users, scopes)
│   ├── federation.py       # /federation/* (Google, GitHub, SAML callbacks)
│   └── health.py           # /health
├── middleware/             # HTTP middleware
│   ├── rate_limiter.py     # In-memory sliding window rate limiter
│   └── security_headers.py # X-Content-Type-Options, X-Frame-Options, etc.
└── templates/              # Jinja2 HTML templates
    ├── login.html, consent.html, device_verify.html, error.html
```

## Conventions

- Entry point in `src/cli.py` contains only CLI wiring
- All entities are frozen dataclasses with tuples (not lists) for immutability
- Async-first: all I/O uses async patterns
- Logging with `%` formatting (lazy evaluation)
- Configuration via `OAUTH2_` prefixed environment variables
- Session middleware for OAuth authorization flow state
- JWT access tokens signed with RS256 (2048-bit RSA)
- Opaque refresh tokens with SHA-256 hashing and rotation

## Quality Gate

Run `make check` before every commit. It runs: lint, format-check, typecheck, security, test-cov (>= 80% coverage).

## Documentation Index

- `.agent_docs/python.md` : Python coding standards and conventions
- `.agent_docs/makefile.md` : Makefile documentation

## Git Workflow

- Every modification must be committed and pushed if a remote repo exists
- Every modification includes docs updates (CLAUDE.md + .agent_docs and README.md + docs)
