# OAuth2 Authorization Server

A fully compliant OAuth 2.1 authorization server with OpenID Connect Core 1.0 support, built with Python and FastAPI.

## Features

- **OAuth 2.1** authorization code flow with mandatory PKCE (S256)
- **Client credentials** grant for service-to-service authentication
- **Device authorization** grant for input-constrained devices
- **Token refresh** with rotation and reuse detection
- **Token introspection** (RFC 7662) and **revocation** (RFC 7009)
- **OpenID Connect**: ID tokens, UserInfo endpoint, Discovery, JWKS
- **JWT access tokens** signed with RS256 (2048-bit RSA keys)
- **User authentication** with Argon2id password hashing and account lockout
- **Social login** federation (Google OIDC, GitHub OAuth)
- **SAML SP** integration for enterprise SSO
- **Consent management** with granular scope control
- **Admin API** for managing clients, users, and scopes
- **Rate limiting** with configurable per-endpoint limits
- **Security headers** on all responses
- **Audit logging** in structured JSONL format
- **OpenTelemetry** tracing
- **Pluggable storage** (JSON file backend included)

## Requirements

- Python 3.13 or later
- uv (package manager)

## Quick Start

```bash
# Install dependencies
make sync

# Generate RSA keys for JWT signing
make run ARGS='generate-keys'

# Create an admin user
make run ARGS='create-admin --email admin@example.com --password SecurePass123!'

# Start the server
make run ARGS='serve'
```

The server starts at `http://localhost:8000` by default.

## Configuration

All settings are configured via environment variables with the `OAUTH2_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH2_HOST` | `0.0.0.0` | Server bind address |
| `OAUTH2_PORT` | `8000` | Server port |
| `OAUTH2_ISSUER_URL` | `http://localhost:8000` | OAuth2 issuer URL |
| `OAUTH2_DEBUG` | `false` | Enable debug mode (Swagger UI) |
| `OAUTH2_RSA_PRIVATE_KEY_PATH` | `keys/private.pem` | RSA private key file |
| `OAUTH2_STORAGE_BACKEND` | `json` | Storage backend type |
| `OAUTH2_JSON_STORAGE_DIR` | `data` | JSON storage directory |
| `OAUTH2_ACCESS_TOKEN_LIFETIME` | `3600` | Access token lifetime (seconds) |
| `OAUTH2_REFRESH_TOKEN_LIFETIME` | `2592000` | Refresh token lifetime (30 days) |
| `OAUTH2_CSRF_SECRET` | (required) | Session middleware secret |
| `OAUTH2_GOOGLE_CLIENT_ID` | | Google OAuth client ID |
| `OAUTH2_GOOGLE_CLIENT_SECRET` | | Google OAuth client secret |
| `OAUTH2_GITHUB_CLIENT_ID` | | GitHub OAuth client ID |
| `OAUTH2_GITHUB_CLIENT_SECRET` | | GitHub OAuth client secret |

## API Endpoints

### OAuth 2.1
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Authorization endpoint |
| `/oauth/token` | POST | Token endpoint (4 grant types) |
| `/oauth/introspect` | POST | Token introspection |
| `/oauth/revoke` | POST | Token revocation |
| `/oauth/device/authorize` | POST | Device authorization |

### OpenID Connect
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |
| `/oidc/userinfo` | GET | UserInfo endpoint |

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | User registration |
| `/auth/consents` | GET | List user consents |
| `/auth/consents/{id}` | DELETE | Revoke consent |

### Admin API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/clients` | GET/POST | List/create clients |
| `/admin/clients/{id}` | PUT/DELETE | Update/deactivate client |
| `/admin/users` | GET | List users |
| `/admin/users/{id}/unlock` | POST | Unlock user account |
| `/admin/scopes` | GET/POST | List/create scopes |
| `/admin/scopes/{name}` | DELETE | Delete scope |

### Health
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |

## Docker

```bash
# Build the Docker image
make docker-build

# Run with Docker Compose
make run-up

# Stop
make run-down
```

## Development

```bash
make sync          # Install dependencies
make test          # Run tests (297 tests)
make test-cov      # Run tests with coverage report
make check         # Full quality gate (lint, format, typecheck, security, tests)
make format        # Auto-format code
make lint-fix      # Auto-fix lint issues
```

## License

MIT
