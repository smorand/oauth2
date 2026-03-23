# OAuth2 Authorization Server — Specification Document

> Generated on: 2026-03-22
> Version: 1.0
> Status: Draft

## 1. Executive Summary

A full OAuth 2.1 compliant authorization server with OpenID Connect support, designed for public/multi-tenant use. The server handles the complete OAuth2 lifecycle: client registration, user authentication, authorization flows, token management, and consent tracking. It features pluggable storage backends (JSON for local development, Firestore for cloud), built-in login/consent pages, social login (Google, GitHub), SAML SP federation, and a role-based admin API. Built with Python 3.13 and FastAPI as a modular monolith.

## 2. Scope

### 2.1 In Scope

- OAuth 2.1 authorization code flow with mandatory PKCE
- OAuth 2.1 client credentials flow
- OAuth 2.1 device authorization grant
- Token refresh with rotation and reuse detection
- Token introspection (RFC 7662)
- Token revocation (RFC 7009)
- OpenID Connect Core 1.0 (ID tokens, UserInfo, Discovery, JWKS)
- JWT access tokens (RS256) with opaque refresh tokens
- User registration and authentication (email + password, Argon2id)
- Social login federation (Google, GitHub via OIDC)
- SAML SP integration (delegate authentication to external SAML IdPs)
- Pluggable storage backends (JSON file, Firestore)
- Pluggable rate limiting (in-memory default, extensible)
- Admin API with role-based access (manage clients, users, scopes)
- Built-in server-rendered login and consent HTML pages (Jinja2)
- Persistent consent records with user-managed revocation
- Account lockout after failed login attempts
- Audit logging for all authentication events
- OpenTelemetry observability (JSONL file traces)
- Docker deployment

### 2.2 Out of Scope (Non-Goals)

- Acting as a SAML Identity Provider (only SAML SP)
- Custom frontend SPA (built-in pages only)
- Cloud Run or GCP-specific deployment (Docker-generic)
- Multi-region replication
- Hardware security module (HSM) key storage
- WebAuthn / FIDO2 / passkeys
- SMS/email MFA (deferred to future version)

## 3. User Personas & Actors

### Developer (Client Owner)
Registers and manages OAuth clients through the admin API. Integrates their applications with this authorization server.

### End User (Resource Owner)
Authenticates via email/password or social login. Grants or denies authorization to third-party applications. Manages their consent records.

### Resource Server
Validates access tokens via introspection or local JWT verification using the JWKS endpoint. Not a human actor.

### Admin
A user with the admin role. Manages clients, users, scopes, and system configuration through the admin API.

### Service Client
A machine-to-machine client that authenticates via client credentials (no user interaction).

### Device/CLI Client
A device or CLI tool that initiates the device authorization grant, where the user authenticates in a browser on a separate device.

## 4. Usage Scenarios

### SC-001: Client Registration

**Actor:** Admin
**Preconditions:** Admin is authenticated with admin role
**Flow:**
1. Admin sends POST /admin/clients with client metadata (name, type, redirect_uris, allowed_scopes, grant_types)
2. Server validates the metadata: name is unique, redirect_uris are valid URLs, scopes exist, grant_types are compatible with client type
3. Server generates client_id (UUID) and client_secret (for confidential/service types)
4. Server stores the client record in the configured storage backend
5. Server returns client_id, client_secret (if applicable), and full client metadata
**Postconditions:** Client is registered and can be used in OAuth flows
**Exceptions:**
- EXC-001a: Duplicate client name → 409 Conflict with error message
- EXC-001b: Invalid redirect_uri format → 400 Bad Request with validation details
- EXC-001c: Unknown scope referenced → 400 Bad Request listing invalid scopes
- EXC-001d: Incompatible grant_type for client type (e.g., authorization_code for service client) → 400 Bad Request
- EXC-001e: Admin not authenticated or lacks admin role → 403 Forbidden

### SC-002: User Registration

**Actor:** End User
**Preconditions:** User does not already have an account with this email
**Flow:**
1. User sends POST /auth/register with email, password, and optional profile fields (name)
2. Server validates email format and password strength (minimum 8 characters, at least one uppercase, one lowercase, one digit)
3. Server checks email uniqueness in storage
4. Server hashes password with Argon2id
5. Server creates user record with default role (user)
6. Server returns user profile (id, email, name, created_at) without password
**Postconditions:** User account exists and can be used for authentication
**Exceptions:**
- EXC-002a: Email already registered → 409 Conflict
- EXC-002b: Weak password → 400 Bad Request with password requirements
- EXC-002c: Invalid email format → 400 Bad Request
- EXC-002d: Missing required fields → 400 Bad Request with field list

### SC-003: Authorization Code Flow + PKCE

**Actor:** End User (via client application)
**Preconditions:** Client is registered with authorization_code grant type. User has an account.
**Flow:**
1. Client redirects user to GET /oauth/authorize with parameters: response_type=code, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method=S256
2. Server validates: client_id exists, redirect_uri matches registered URIs (exact match), code_challenge is present (mandatory per OAuth 2.1), scope is valid for this client
3. If user is not authenticated, server renders login page
4. User submits credentials (email + password)
5. Server authenticates user (checks password hash, verifies account is not locked)
6. Server checks if user has an existing valid consent for this client+scopes
7. If no existing consent, server renders consent page showing requested scopes and client info
8. User approves consent
9. Server stores consent record (user_id, client_id, scopes, granted_at)
10. Server generates authorization code (random, 128-bit), stores it with: client_id, redirect_uri, user_id, scope, code_challenge, expiry (5 min)
11. Server redirects to redirect_uri with code and state parameters
12. Client sends POST /oauth/token with grant_type=authorization_code, code, redirect_uri, client_id, code_verifier
13. Server validates: code is valid and not expired, redirect_uri matches, code_verifier matches code_challenge (S256), client is authenticated (secret for confidential, none for public)
14. Server invalidates the authorization code (one-time use)
15. Server generates JWT access token (1h) with claims: sub, scope, iss, aud, exp, iat, jti
16. Server generates opaque refresh token (30d), stores token family ID
17. Server generates ID token (JWT) with claims: sub, iss, aud, exp, iat, nonce, auth_time
18. Server returns token response: access_token, token_type=Bearer, expires_in, refresh_token, id_token, scope
**Postconditions:** Client has valid access token, refresh token, and ID token. Consent is recorded.
**Exceptions:**
- EXC-003a: Missing code_challenge → 400 Bad Request ("PKCE required per OAuth 2.1")
- EXC-003b: Invalid redirect_uri → Error displayed to user (no redirect to prevent open redirect)
- EXC-003c: Invalid client_id → 400 Bad Request
- EXC-003d: User denies consent → Redirect to redirect_uri with error=access_denied
- EXC-003e: Authorization code expired → 400 Bad Request with error=invalid_grant
- EXC-003f: Authorization code already used → 400 Bad Request, revoke all tokens issued from this code
- EXC-003g: code_verifier mismatch → 400 Bad Request with error=invalid_grant
- EXC-003h: Account locked → Login page shows lockout message with remaining time
- EXC-003i: Invalid credentials → Login page shows error, increment failed attempt counter
**Cross-scenario notes:** If user has existing consent (SC-011), steps 7-9 are skipped.

### SC-004: Client Credentials Flow

**Actor:** Service Client
**Preconditions:** Client is registered with client_credentials grant type (service client type)
**Flow:**
1. Client sends POST /oauth/token with grant_type=client_credentials, client_id, client_secret, scope
2. Server authenticates client via client_id + client_secret (HTTP Basic or POST body)
3. Server validates requested scope is within client's allowed scopes
4. Server generates JWT access token (1h) with claims: sub=client_id, scope, iss, aud, exp, iat, jti
5. Server returns token response: access_token, token_type=Bearer, expires_in, scope (no refresh token)
**Postconditions:** Client has valid access token for service-to-service calls
**Exceptions:**
- EXC-004a: Invalid client credentials → 401 Unauthorized
- EXC-004b: Client type is not "service" → 400 Bad Request with error=unauthorized_client
- EXC-004c: Requested scope exceeds allowed scopes → 400 Bad Request with error=invalid_scope

### SC-005: Device Code Flow

**Actor:** Device/CLI Client + End User (on separate browser)
**Preconditions:** Client is registered with urn:ietf:params:oauth:grant-type:device_code grant type
**Flow:**
1. Device sends POST /oauth/device/authorize with client_id and scope
2. Server generates device_code (256-bit random), user_code (8 alphanumeric characters), verification_uri, verification_uri_complete (with user_code embedded), interval (polling interval in seconds, default 5), expires_in (15 min)
3. Server stores device code record: device_code, user_code, client_id, scope, expiry, status=pending
4. Server returns device authorization response
5. Device displays user_code and verification_uri to the user
6. User opens verification_uri in browser, enters user_code
7. Server authenticates user (login page if not authenticated)
8. Server renders consent page for the device client's requested scopes
9. User approves consent
10. Server updates device code status to approved, associates user_id
11. Device polls POST /oauth/token with grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code, client_id
12. Server detects approval, generates access token + refresh token + ID token
13. Server returns token response
**Postconditions:** Device has valid tokens. Consent is recorded.
**Exceptions:**
- EXC-005a: Device polls before approval → 400 with error=authorization_pending
- EXC-005b: Device polls too fast → 400 with error=slow_down (increase interval by 5s)
- EXC-005c: Device code expired → 400 with error=expired_token
- EXC-005d: User denies consent → Next poll returns error=access_denied
- EXC-005e: Invalid user_code entered → Error page, allow retry

### SC-006: Token Refresh

**Actor:** Client application
**Preconditions:** Client has a valid, non-expired refresh token
**Flow:**
1. Client sends POST /oauth/token with grant_type=refresh_token, refresh_token, client_id (+ client_secret for confidential clients)
2. Server validates refresh token: exists, not expired, not revoked, belongs to client_id
3. Server implements token rotation: generates new refresh token, invalidates old one, maintains token family ID
4. Server generates new JWT access token with same or narrower scope
5. Server returns token response: new access_token, new refresh_token, expires_in, scope
**Postconditions:** Old refresh token is invalidated. New token pair is active.
**Exceptions:**
- EXC-006a: Refresh token expired → 400 with error=invalid_grant
- EXC-006b: Refresh token already used (reuse detection) → Revoke entire token family, return 400 with error=invalid_grant
- EXC-006c: Refresh token revoked → 400 with error=invalid_grant
- EXC-006d: Client mismatch → 400 with error=invalid_grant
**Cross-scenario notes:** Reuse detection (EXC-006b) is critical for stolen token scenarios. When triggered, all access and refresh tokens in the family are revoked.

### SC-007: Token Introspection

**Actor:** Resource Server
**Preconditions:** Resource server has valid client credentials
**Flow:**
1. Resource server sends POST /oauth/introspect with token parameter and client authentication
2. Server authenticates the requesting client
3. Server inspects the token: if JWT access token, validate signature and claims; if opaque refresh token, look up in storage
4. Server returns introspection response: active (boolean), and if active: sub, scope, client_id, token_type, exp, iat, iss
**Postconditions:** Resource server knows if token is valid and its associated metadata
**Exceptions:**
- EXC-007a: Unauthenticated request → 401 Unauthorized
- EXC-007b: Expired/revoked/invalid token → Return {"active": false} (not an error)
- EXC-007c: Malformed token → Return {"active": false}

### SC-008: Token Revocation

**Actor:** Client application or End User
**Preconditions:** A valid token exists
**Flow:**
1. Client sends POST /oauth/revoke with token and token_type_hint (access_token or refresh_token), plus client authentication
2. Server authenticates the client
3. Server identifies the token type (access or refresh)
4. If refresh token: revoke the refresh token and all access tokens in its family
5. If access token: add to revocation list (for introspection checks; JWTs remain valid until expiry for stateless validation)
6. Server returns 200 OK (always, even if token was already invalid, per RFC 7009)
**Postconditions:** Token is revoked. Introspection will return active=false.
**Exceptions:**
- EXC-008a: Unauthenticated request → 401 Unauthorized
- EXC-008b: Token belongs to different client → Ignore silently (return 200 per RFC)

### SC-009: Social Login via Google

**Actor:** End User
**Preconditions:** Google OIDC provider is configured (client_id, client_secret from Google Cloud Console)
**Flow:**
1. During authorization flow (SC-003 step 3), user clicks "Sign in with Google" on login page
2. Server redirects to Google's authorization endpoint with: client_id (Google's), redirect_uri (back to this server), scope=openid email profile, state (CSRF), nonce
3. User authenticates with Google
4. Google redirects back to this server with authorization code
5. Server exchanges code for tokens with Google's token endpoint
6. Server validates Google's ID token (signature, iss, aud, exp, nonce)
7. Server extracts user info (email, name, picture) from ID token
8. Server looks up user by Google subject ID (linked account) or by email
9. If user exists with linked Google account → authenticate
10. If user exists with same email but no Google link → link Google account and authenticate
11. If no user exists → create new user account with Google profile, mark as social login
12. Server continues authorization flow from SC-003 step 6 (consent check)
**Postconditions:** User is authenticated. Google account is linked to local user.
**Exceptions:**
- EXC-009a: Google returns error → Display error on login page
- EXC-009b: State mismatch (CSRF) → 400 Bad Request
- EXC-009c: Google ID token validation fails → Display error on login page
- EXC-009d: Email from Google matches existing account with different social provider → Link both providers
**Cross-scenario notes:** Social login creates/links a local user, then proceeds with normal OAuth flow (SC-003).

### SC-010: Social Login via GitHub

**Actor:** End User
**Preconditions:** GitHub OAuth app is configured (client_id, client_secret)
**Flow:**
1. During authorization flow, user clicks "Sign in with GitHub" on login page
2. Server redirects to GitHub's authorization endpoint with: client_id (GitHub's), redirect_uri, scope=user:email, state
3. User authenticates with GitHub
4. GitHub redirects back with authorization code
5. Server exchanges code for access token with GitHub's token endpoint
6. Server fetches user profile from GitHub API (/user and /user/emails)
7. Server extracts email (primary verified), name, avatar
8. Same user lookup/link/create logic as SC-009 steps 8-11
9. Server continues authorization flow
**Postconditions:** User is authenticated. GitHub account is linked to local user.
**Exceptions:**
- EXC-010a: GitHub returns error → Display error on login page
- EXC-010b: State mismatch → 400 Bad Request
- EXC-010c: GitHub user has no verified email → Display error requesting email verification on GitHub
- EXC-010d: GitHub API rate limited → Display retry message

### SC-011: Consent Management

**Actor:** End User
**Preconditions:** User is authenticated
**Flow:**
1. User sends GET /auth/consents to view all active consent grants
2. Server returns list of consents: client name, scopes granted, granted_at
3. User sends DELETE /auth/consents/{consent_id} to revoke a specific consent
4. Server revokes the consent record
5. Server revokes all active tokens (access + refresh) issued under this consent
6. Server returns 204 No Content
**Postconditions:** Consent is revoked. All associated tokens are invalidated.
**Exceptions:**
- EXC-011a: Consent not found → 404 Not Found
- EXC-011b: Consent belongs to different user → 403 Forbidden
**Cross-scenario notes:** Revoking consent (step 5) triggers token revocation (SC-008 logic).

### SC-012: OIDC UserInfo

**Actor:** Client application (with valid access token)
**Preconditions:** Access token has openid scope
**Flow:**
1. Client sends GET /oidc/userinfo with Authorization: Bearer <access_token>
2. Server validates access token (JWT signature, expiry, revocation status)
3. Server extracts user_id from token's sub claim
4. Server fetches user profile from storage
5. Server returns claims based on granted scopes: sub (always), name/family_name/given_name (profile), email/email_verified (email)
**Postconditions:** Client has user profile information
**Exceptions:**
- EXC-012a: Missing or invalid access token → 401 Unauthorized with WWW-Authenticate header
- EXC-012b: Token lacks openid scope → 403 Forbidden
- EXC-012c: User not found (deleted account) → 404 Not Found

### SC-013: SAML SP Authentication

**Actor:** End User (authenticating via corporate SAML IdP)
**Preconditions:** SAML IdP is configured (metadata URL or manual config: entity_id, SSO URL, X.509 certificate)
**Flow:**
1. During authorization flow (SC-003 step 3), user clicks "Sign in with [Corporate IdP]" on login page
2. Server generates SAML AuthnRequest (signed)
3. Server redirects user to SAML IdP's SSO URL with the AuthnRequest (HTTP-Redirect binding)
4. User authenticates at the corporate IdP
5. IdP redirects back to this server's ACS (Assertion Consumer Service) URL with SAML Response (HTTP-POST binding)
6. Server validates SAML Response: signature, issuer, audience, time conditions, assertion signature
7. Server extracts user attributes: NameID (email), name, groups
8. Same user lookup/link/create logic as SC-009 steps 8-11 (using SAML NameID as external ID)
9. Server continues authorization flow from SC-003 step 6
**Postconditions:** User is authenticated via SAML. Account is linked to SAML identity.
**Exceptions:**
- EXC-013a: SAML Response signature invalid → Display error on login page
- EXC-013b: SAML Response expired → Display error, suggest retry
- EXC-013c: SAML IdP unreachable → Display error with IdP name
- EXC-013d: NameID missing from assertion → Display error

### SC-014: Admin Operations

**Actor:** Admin
**Preconditions:** Admin is authenticated with admin role
**Flow:**
Admin can perform the following operations via the admin API:

**Client management:**
1. POST /admin/clients — Create client (SC-001)
2. GET /admin/clients — List all clients (with pagination)
3. GET /admin/clients/{id} — Get client details
4. PATCH /admin/clients/{id} — Update client (name, redirect_uris, scopes, status)
5. DELETE /admin/clients/{id} — Deactivate client (soft delete)
6. POST /admin/clients/{id}/rotate-secret — Generate new client_secret

**User management:**
7. GET /admin/users — List users (with pagination, search)
8. GET /admin/users/{id} — Get user details
9. PATCH /admin/users/{id} — Update user (role, status, profile)
10. DELETE /admin/users/{id} — Deactivate user (soft delete)
11. POST /admin/users/{id}/unlock — Unlock locked account

**Scope management:**
12. POST /admin/scopes — Create custom scope (name, description)
13. GET /admin/scopes — List all scopes
14. DELETE /admin/scopes/{name} — Delete scope (if not in use)

**Postconditions:** Requested admin operation is completed
**Exceptions:**
- EXC-014a: Non-admin user attempts admin operation → 403 Forbidden
- EXC-014b: Entity not found → 404 Not Found
- EXC-014c: Scope in use by active clients → 409 Conflict (cannot delete)
- EXC-014d: Attempt to delete last admin user → 409 Conflict
**Cross-scenario notes:** Deactivating a client (step 5) revokes all tokens for that client.

## 5. Functional Requirements

### FR-001: OAuth 2.1 Authorization Code Flow with PKCE
- **Description:** The server must implement the authorization code grant with mandatory PKCE (RFC 7636). PKCE is required for all clients (public and confidential) per OAuth 2.1.
- **Inputs:** client_id, redirect_uri, response_type=code, scope, state, code_challenge, code_challenge_method
- **Outputs:** Authorization code (via redirect), then token set (access_token, refresh_token, id_token)
- **Business Rules:** code_challenge_method must be S256 (plain is not allowed per OAuth 2.1). Authorization codes are single-use with 5-minute expiry. Redirect URI must exact-match registered URIs.
- **Priority:** Must-have

### FR-002: OAuth 2.1 Client Credentials Flow
- **Description:** The server must issue access tokens to authenticated service clients without user involvement.
- **Inputs:** grant_type=client_credentials, client_id, client_secret, scope
- **Outputs:** access_token, token_type, expires_in, scope
- **Business Rules:** Only "service" type clients may use this flow. No refresh token is issued. Scope must be within client's allowed scopes.
- **Priority:** Must-have

### FR-003: OAuth 2.1 Device Authorization Grant
- **Description:** The server must support the device authorization grant (RFC 8628) for devices with limited input capability.
- **Inputs:** client_id, scope (device request); device_code, client_id (polling)
- **Outputs:** device_code, user_code, verification_uri, verification_uri_complete, interval, expires_in
- **Business Rules:** User codes must be 8 alphanumeric characters (easy to type). Polling interval starts at 5 seconds. Server must enforce slow_down when client polls too fast. Device codes expire after 15 minutes.
- **Priority:** Must-have

### FR-004: Token Refresh with Rotation
- **Description:** The server must issue new token pairs when a valid refresh token is presented, implementing token rotation with reuse detection.
- **Inputs:** grant_type=refresh_token, refresh_token, client_id, client_secret (confidential clients)
- **Outputs:** New access_token, new refresh_token, expires_in, scope
- **Business Rules:** Each refresh token can only be used once. A refresh token family ID tracks the chain. If a previously used refresh token is presented (reuse), the entire family must be revoked immediately.
- **Priority:** Must-have

### FR-005: JWT Access Tokens (RS256)
- **Description:** Access tokens must be signed JWTs using RS256 algorithm.
- **Inputs:** User/client claims, scope, token lifetime
- **Outputs:** Signed JWT with standard claims (iss, sub, aud, exp, iat, jti, scope)
- **Business Rules:** Token lifetime is 1 hour. JTI (JWT ID) must be unique. The signing key pair must be rotatable. Public keys must be exposed via JWKS endpoint.
- **Priority:** Must-have

### FR-006: Opaque Refresh Tokens
- **Description:** Refresh tokens must be opaque (random strings) stored server-side.
- **Inputs:** User context, client context, scope
- **Outputs:** 256-bit random token string
- **Business Rules:** Refresh token lifetime is 30 days. Stored with: token hash, user_id, client_id, scope, family_id, created_at, expires_at, used (boolean).
- **Priority:** Must-have

### FR-007: Token Introspection (RFC 7662)
- **Description:** The server must expose a token introspection endpoint for resource servers.
- **Inputs:** token, token_type_hint (optional), client authentication
- **Outputs:** JSON with active (boolean) and token metadata if active
- **Business Rules:** Only authenticated clients can introspect. Invalid/expired/revoked tokens return {"active": false}. Must check both JWT validity and revocation list.
- **Priority:** Must-have

### FR-008: Token Revocation (RFC 7009)
- **Description:** The server must allow clients to revoke tokens.
- **Inputs:** token, token_type_hint (optional), client authentication
- **Outputs:** 200 OK (always, per RFC)
- **Business Rules:** Revoking a refresh token must also revoke all access tokens in its family. The endpoint must always return 200 (even for invalid tokens) to prevent token scanning.
- **Priority:** Must-have

### FR-009: OpenID Connect Core
- **Description:** The server must implement OIDC Core 1.0: ID token issuance, UserInfo endpoint, Discovery document, and JWKS endpoint.
- **Inputs:** OIDC requests (authorize with openid scope, UserInfo with bearer token)
- **Outputs:** ID tokens (JWT), UserInfo JSON, Discovery JSON, JWKS JSON
- **Business Rules:** ID tokens must include: iss, sub, aud, exp, iat, auth_time, nonce (if provided). Claims returned by UserInfo depend on granted scopes (profile, email). Discovery document at /.well-known/openid-configuration must list all supported endpoints, scopes, and algorithms.
- **Priority:** Must-have

### FR-010: User Registration and Authentication
- **Description:** Users must be able to register with email+password and authenticate.
- **Inputs:** email, password, profile fields (registration); email, password (login)
- **Outputs:** User profile (registration); authenticated session (login)
- **Business Rules:** Passwords hashed with Argon2id. Minimum 8 characters, 1 uppercase, 1 lowercase, 1 digit. Email must be unique. Account lockout after 5 failed attempts for 30 minutes.
- **Priority:** Must-have

### FR-011: Social Login (Google + GitHub)
- **Description:** Users must be able to authenticate via Google or GitHub OIDC/OAuth.
- **Inputs:** Social provider selection, OAuth callback from provider
- **Outputs:** Authenticated session, linked social account
- **Business Rules:** Social login must link to existing accounts by email. If no account exists, create one. A user can link multiple social providers. Google uses OIDC (ID token validation). GitHub uses OAuth2 + API calls for user info.
- **Priority:** Must-have

### FR-012: SAML SP Integration
- **Description:** The server must act as a SAML Service Provider, delegating authentication to configured SAML Identity Providers.
- **Inputs:** SAML IdP metadata (entity_id, SSO URL, X.509 cert), SAML Response
- **Outputs:** Authenticated session
- **Business Rules:** Must support HTTP-Redirect binding for AuthnRequest and HTTP-POST binding for Response. Must validate assertion signatures, time conditions, and audience. NameID used as external identifier for account linking.
- **Priority:** Must-have

### FR-013: Pluggable Storage Backend
- **Description:** All data persistence must go through an abstract storage layer with interchangeable backends.
- **Inputs:** STORAGE_BACKEND environment variable (json, firestore)
- **Outputs:** Consistent data access regardless of backend
- **Business Rules:** Storage interface defined as Python Protocol. JSON backend stores data in a local directory (one file per collection). Firestore backend uses GCP Firestore. Both backends must pass identical integration tests.
- **Priority:** Must-have

### FR-014: Client Management (Admin API)
- **Description:** Admins must be able to create, read, update, and deactivate OAuth clients.
- **Inputs:** Client metadata (name, type, redirect_uris, scopes, grant_types)
- **Outputs:** Client details with generated credentials
- **Business Rules:** Three client types: confidential (has secret), public (no secret, PKCE required), service (has secret, client_credentials only). Client secrets can be rotated. Deactivation is soft-delete (revokes all tokens). Client names must be unique.
- **Priority:** Must-have

### FR-015: Scope Management (Admin API)
- **Description:** Admins must be able to define custom scopes.
- **Inputs:** scope name, description
- **Outputs:** Scope record
- **Business Rules:** Standard OIDC scopes (openid, profile, email) are always available. Custom scopes cannot use reserved names. Scopes in use by active clients cannot be deleted.
- **Priority:** Must-have

### FR-016: Consent Management
- **Description:** The server must track user consent and allow users to view and revoke their grants.
- **Inputs:** User authentication, consent_id (for revocation)
- **Outputs:** List of active consents, revocation confirmation
- **Business Rules:** Consent is per user+client+scope combination. If user has existing consent for a client requesting the same or subset of scopes, skip consent screen. Revoking consent must revoke all associated tokens.
- **Priority:** Must-have

### FR-017: Account Lockout
- **Description:** The server must lock user accounts after repeated failed login attempts.
- **Inputs:** Login attempts
- **Outputs:** Lockout status, remaining time
- **Business Rules:** Lock after 5 consecutive failed attempts. Lockout duration is 30 minutes. Successful login resets the counter. Admin can manually unlock accounts. Lockout applies to password login only (not social/SAML).
- **Priority:** Must-have

### FR-018: Rate Limiting
- **Description:** The server must rate-limit requests to prevent abuse.
- **Inputs:** HTTP requests
- **Outputs:** 429 Too Many Requests when exceeded
- **Business Rules:** Pluggable implementation (in-memory default). Rate limits per endpoint category: token endpoint (30/min per client), authorize endpoint (60/min per IP), login (10/min per IP), admin API (120/min per admin user). Response must include Retry-After header.
- **Priority:** Must-have

### FR-019: Audit Logging
- **Description:** All authentication and authorization events must be logged for security audit.
- **Inputs:** Auth events (login, token issue, revocation, admin ops)
- **Outputs:** Structured audit log entries
- **Business Rules:** Each entry must include: timestamp, event_type, actor (user_id or client_id), IP address, result (success/failure), details. Audit logs are append-only. Must not log sensitive data (passwords, tokens, secrets).
- **Priority:** Must-have

### FR-020: Built-in Login and Consent Pages
- **Description:** The server must render HTML login and consent pages for browser-based flows.
- **Inputs:** Authorization request context
- **Outputs:** HTML pages (Jinja2 templates)
- **Business Rules:** Login page shows: email/password form, social login buttons (if configured), SAML login button (if configured). Consent page shows: client name, requested scopes with descriptions, approve/deny buttons. CSRF protection on all forms.
- **Priority:** Must-have

### FR-021: OIDC Discovery and JWKS
- **Description:** The server must expose standard OIDC discovery and key endpoints.
- **Inputs:** GET requests to well-known URLs
- **Outputs:** JSON documents
- **Business Rules:** Discovery at /.well-known/openid-configuration must list: issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, introspection_endpoint, revocation_endpoint, device_authorization_endpoint, scopes_supported, response_types_supported, grant_types_supported, token_endpoint_auth_methods_supported, subject_types_supported, id_token_signing_alg_values_supported. JWKS at /.well-known/jwks.json must expose current (and recently rotated) public keys.
- **Priority:** Must-have

### FR-022: PKCE Enforcement
- **Description:** PKCE must be mandatory for all authorization code requests per OAuth 2.1.
- **Inputs:** code_challenge, code_challenge_method in authorize; code_verifier in token
- **Outputs:** Validation result
- **Business Rules:** Only S256 method is supported (plain is forbidden per OAuth 2.1). Missing code_challenge must be rejected. code_verifier must match: BASE64URL(SHA256(code_verifier)) == code_challenge.
- **Priority:** Must-have

### FR-023: Refresh Token Reuse Detection
- **Description:** If a refresh token that has already been used is presented, the entire token family must be revoked.
- **Inputs:** Previously used refresh token
- **Outputs:** Error response + family revocation
- **Business Rules:** Each refresh token has a family_id. When reuse is detected, all tokens (access + refresh) in that family are revoked. This protects against stolen refresh tokens.
- **Priority:** Must-have

## 6. Non-Functional Requirements

### 6.1 Performance
- No specific SLA. Best-effort performance optimization.
- Token endpoint must handle typical load without queueing (target: sub-second response under normal conditions)
- JWT validation (JWKS fetch) should be cacheable by resource servers

### 6.2 Security
- **Password hashing:** Argon2id with recommended parameters (memory: 64MB, iterations: 3, parallelism: 4)
- **Token signing:** RS256 with 2048-bit RSA keys, rotatable
- **PKCE:** Mandatory for all authorization code flows (OAuth 2.1)
- **Redirect URI:** Strict exact-match validation only
- **CSRF:** State parameter in OAuth flows, CSRF tokens on HTML forms
- **Account lockout:** 5 failed attempts → 30-minute lockout
- **Refresh token rotation:** Mandatory with reuse detection and family revocation
- **Secret storage:** Client secrets stored as hashes (bcrypt), never in plaintext
- **Audit logging:** All auth events logged (no sensitive data in logs)
- **Headers:** Security headers on all responses (X-Content-Type-Options, X-Frame-Options, Cache-Control on token responses)
- **HTTPS:** Required in production (configurable for local dev)

### 6.3 Usability
- Login and consent pages must be functional HTML (no JavaScript framework required)
- Error messages must be clear and actionable
- Admin API must follow RESTful conventions with consistent error format

### 6.4 Reliability
- Stateless JWT access tokens enable resource server resilience even if auth server is temporarily down
- Storage backend must handle concurrent writes safely (JSON backend uses file locking; Firestore uses transactions)
- Graceful degradation: if rate limiter backend is unavailable, allow requests (fail open for availability)

### 6.5 Observability
- **Collector:** JSONL file
- **Trace file path:** traces/app.jsonl
- **What to trace:** API calls (INFO), storage operations (DEBUG), token operations (INFO), auth events (INFO), social/SAML federation calls (INFO), errors (ERROR)
- **Sensitive data exclusion:** Passwords, tokens, client secrets, SAML assertions must NEVER appear in traces
- **Audit log:** Separate structured audit log for security events (distinct from observability traces)

### 6.6 Deployment
- **Container:** Docker image (multi-stage build, non-root user, Python 3.13 slim)
- **Configuration:** Environment variables for all settings (STORAGE_BACKEND, ISSUER_URL, RSA_PRIVATE_KEY_PATH, GOOGLE_CLIENT_ID, etc.)
- **Local development:** docker-compose with JSON storage backend
- **Health check:** GET /health endpoint returning server status and storage connectivity

### 6.7 Scalability
- Stateless application design (no in-process session state beyond rate limiter cache)
- Horizontal scaling supported when using Firestore backend
- JSON backend is single-instance only (local dev)

## 7. Data Model

### User
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary identifier |
| email | string | Unique, lowercase |
| password_hash | string | Argon2id hash (null for social-only users) |
| name | string | Display name |
| role | enum | user, admin |
| status | enum | active, locked, deactivated |
| failed_login_attempts | int | Counter for lockout |
| locked_until | datetime | Lockout expiry (null if not locked) |
| created_at | datetime | Account creation time |
| updated_at | datetime | Last modification |

### Social Account (linked to User)
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary identifier |
| user_id | UUID | FK to User |
| provider | enum | google, github, saml |
| provider_user_id | string | External user ID from provider |
| provider_email | string | Email from provider |
| provider_name | string | Name from provider |
| linked_at | datetime | When the link was created |

### Client
| Field | Type | Description |
|-------|------|-------------|
| id | UUID (client_id) | Primary identifier |
| name | string | Unique display name |
| type | enum | confidential, public, service |
| secret_hash | string | Hashed client_secret (null for public) |
| redirect_uris | list[string] | Registered redirect URIs |
| allowed_scopes | list[string] | Scopes this client can request |
| grant_types | list[string] | Allowed grant types |
| status | enum | active, deactivated |
| created_by | UUID | Admin user who created it |
| created_at | datetime | Creation time |
| updated_at | datetime | Last modification |

### Authorization Code
| Field | Type | Description |
|-------|------|-------------|
| code_hash | string | Hashed authorization code |
| client_id | UUID | FK to Client |
| user_id | UUID | FK to User |
| redirect_uri | string | Must match on exchange |
| scope | string | Granted scopes |
| code_challenge | string | PKCE code challenge |
| code_challenge_method | string | S256 |
| nonce | string | OIDC nonce (optional) |
| expires_at | datetime | Code expiry (5 min) |
| used | boolean | Single-use flag |

### Refresh Token
| Field | Type | Description |
|-------|------|-------------|
| token_hash | string | Hashed token value |
| family_id | UUID | Token rotation family |
| user_id | UUID | FK to User |
| client_id | UUID | FK to Client |
| scope | string | Granted scopes |
| expires_at | datetime | Token expiry (30 days) |
| used | boolean | Rotation tracking |
| revoked | boolean | Revocation flag |
| created_at | datetime | Issuance time |

### Consent
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary identifier |
| user_id | UUID | FK to User |
| client_id | UUID | FK to Client |
| scopes | list[string] | Granted scopes |
| granted_at | datetime | When consent was given |
| revoked_at | datetime | When revoked (null if active) |

### Device Code
| Field | Type | Description |
|-------|------|-------------|
| device_code_hash | string | Hashed device code |
| user_code | string | Human-readable code |
| client_id | UUID | FK to Client |
| scope | string | Requested scopes |
| user_id | UUID | FK to User (set on approval) |
| status | enum | pending, approved, denied |
| interval | int | Polling interval (seconds) |
| expires_at | datetime | Code expiry (15 min) |
| last_polled_at | datetime | For slow_down enforcement |

### Scope
| Field | Type | Description |
|-------|------|-------------|
| name | string | Primary identifier (e.g., "read:users") |
| description | string | Human-readable description |
| built_in | boolean | True for openid, profile, email |
| created_at | datetime | Creation time |

### Token Revocation Entry
| Field | Type | Description |
|-------|------|-------------|
| jti | string | JWT ID of revoked access token |
| revoked_at | datetime | When revoked |
| expires_at | datetime | Original token expiry (for cleanup) |

### SAML IdP Configuration
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary identifier |
| name | string | Display name (shown on login page) |
| entity_id | string | SAML IdP entity ID |
| sso_url | string | Single Sign-On URL |
| certificate | string | X.509 certificate for signature validation |
| attribute_mapping | dict | Maps SAML attributes to user fields |
| status | enum | active, deactivated |

## 8. Documentation Requirements

All documentation listed below MUST be created and maintained as part of this project.

### 8.1 README.md
- Project description, purpose, and audience
- Prerequisites and installation instructions
- How to run, build, and test the project
- Configuration and environment variables
- Quick start guide for setting up a local dev instance
- API endpoint overview

### 8.2 CLAUDE.md & .agent_docs/
- `CLAUDE.md`: Compact index with project overview, key commands, essential conventions, and documentation index referencing `.agent_docs/` files
- `.agent_docs/architecture.md`: Module structure, data flow, storage abstraction pattern
- `.agent_docs/oauth-flows.md`: Detailed OAuth flow documentation with sequence diagrams
- `.agent_docs/api-reference.md`: All endpoints with request/response formats
- `.agent_docs/security.md`: Security decisions, threat model, crypto parameters
- `.agent_docs/deployment.md`: Docker configuration, environment variables, production checklist
- Must be kept in sync with code changes

### 8.3 docs/*
- `docs/index.md`: User-facing documentation overview
- `docs/getting-started.md`: Step-by-step setup guide
- `docs/configuration.md`: All environment variables and their effects
- `docs/api-reference.md`: Complete API reference for developers integrating with this server
- `docs/admin-guide.md`: Admin API usage guide
- `docs/storage-backends.md`: How to configure and extend storage backends
- `docs/social-login.md`: Setting up Google and GitHub social login
- `docs/saml-integration.md`: Configuring SAML IdP integration

## 9. Traceability Matrix

| Scenario | Functional Req | E2E Tests (Happy) | E2E Tests (Failure) | E2E Tests (Edge) |
|----------|---------------|-------------------|---------------------|-------------------|
| SC-001 | FR-014 | E2E-011 | EXC-001a-e via E2E-022 | E2E-042 |
| SC-002 | FR-010 | E2E-010 | EXC-002a-d via E2E-010 | E2E-032 |
| SC-003 | FR-001, FR-005, FR-006, FR-009, FR-020, FR-022 | E2E-001 | E2E-015, E2E-016, E2E-017, E2E-024, E2E-027 | E2E-031, E2E-034, E2E-037 |
| SC-004 | FR-002, FR-005 | E2E-002 | E2E-020, E2E-023, E2E-026 | E2E-035 |
| SC-005 | FR-003 | E2E-003 | E2E-025 | E2E-038 |
| SC-006 | FR-004, FR-006, FR-023 | E2E-004 | E2E-018, E2E-030 | E2E-036 |
| SC-007 | FR-007 | E2E-005 | E2E-019, E2E-028, E2E-030 | E2E-039 |
| SC-008 | FR-008 | E2E-006 | EXC-008a-b via E2E-006 | E2E-041 |
| SC-009 | FR-011 | E2E-012 | EXC-009a-d via E2E-012 | E2E-045 |
| SC-010 | FR-011 | E2E-013 | EXC-010a-d via E2E-013 | E2E-045 |
| SC-011 | FR-016 | E2E-041 (consent revoke) | EXC-011a-b via E2E-041 | E2E-037 |
| SC-012 | FR-009 | E2E-007 | EXC-012a-c via E2E-007 | E2E-032 |
| SC-013 | FR-012 | E2E-014 | EXC-013a-d via E2E-014 | E2E-046 |
| SC-014 | FR-014, FR-015, FR-010 | E2E-011 | E2E-022 | E2E-042 |
| Cross | FR-017 | — | E2E-021 | — |
| Cross | FR-018 | — | E2E-029 | — |
| Cross | FR-021 | E2E-008, E2E-009 | — | E2E-039 |
| Cross | FR-019 | (audit verified in all tests) | — | — |
| Cross | FR-013 | E2E-040 | — | E2E-040 |
| Cross | — | — | — | E2E-043, E2E-044 |

## 10. End-to-End Test Suite

### 10.1 Test Summary

| Test ID | Category | Scenario | FR refs | Priority |
|---------|----------|----------|---------|----------|
| E2E-001 | Core Journey | SC-003 | FR-001, FR-005, FR-006, FR-009, FR-022 | Critical |
| E2E-002 | Core Journey | SC-004 | FR-002, FR-005 | Critical |
| E2E-003 | Core Journey | SC-005 | FR-003 | Critical |
| E2E-004 | Core Journey | SC-006 | FR-004, FR-006, FR-023 | Critical |
| E2E-005 | Core Journey | SC-007 | FR-007 | Critical |
| E2E-006 | Core Journey | SC-008 | FR-008 | Critical |
| E2E-007 | Core Journey | SC-012 | FR-009 | High |
| E2E-008 | Core Journey | SC-012 | FR-021 | High |
| E2E-009 | Core Journey | SC-012 | FR-021 | High |
| E2E-010 | Core Journey | SC-002 | FR-010 | Critical |
| E2E-011 | Core Journey | SC-001, SC-014 | FR-014 | Critical |
| E2E-012 | Core Journey | SC-009 | FR-011 | High |
| E2E-013 | Core Journey | SC-010 | FR-011 | High |
| E2E-014 | Core Journey | SC-013 | FR-012 | High |
| E2E-015 | Failure | SC-003 | FR-001 | Critical |
| E2E-016 | Failure | SC-003 | FR-022 | Critical |
| E2E-017 | Failure | SC-003 | FR-001 | Critical |
| E2E-018 | Failure | SC-006 | FR-023 | Critical |
| E2E-019 | Failure | SC-007 | FR-007 | High |
| E2E-020 | Failure | SC-004 | FR-002 | High |
| E2E-021 | Security | SC-003 | FR-017 | Critical |
| E2E-022 | Security | SC-014 | FR-014 | Critical |
| E2E-023 | Failure | SC-004 | FR-002 | High |
| E2E-024 | Failure | SC-003 | FR-022 | Critical |
| E2E-025 | Failure | SC-005 | FR-003 | High |
| E2E-026 | Failure | SC-004 | FR-015 | High |
| E2E-027 | Security | SC-003 | FR-020 | High |
| E2E-028 | Failure | SC-007, SC-008 | FR-007, FR-008 | High |
| E2E-029 | Security | Cross | FR-018 | High |
| E2E-030 | Security | SC-006, SC-007 | FR-005 | High |
| E2E-031 | Edge Case | SC-003 | FR-001, FR-009 | Medium |
| E2E-032 | Edge Case | SC-002, SC-012 | FR-010, FR-009 | Medium |
| E2E-033 | Edge Case | SC-003 | FR-001 | Medium |
| E2E-034 | Edge Case | SC-003 | FR-001 | Medium |
| E2E-035 | Edge Case | SC-004 | FR-002, FR-015 | Medium |
| E2E-036 | Edge Case | SC-006 | FR-004 | Medium |
| E2E-037 | Edge Case | SC-003, SC-011 | FR-016 | Medium |
| E2E-038 | Edge Case | SC-005 | FR-003 | Medium |
| E2E-039 | Edge Case | SC-007 | FR-005, FR-021 | Medium |
| E2E-040 | Edge Case | Cross | FR-013 | Medium |
| E2E-041 | Edge Case | SC-011 | FR-016, FR-008 | High |
| E2E-042 | Edge Case | SC-001, SC-014 | FR-014 | Medium |
| E2E-043 | Cross-Scenario | SC-003, SC-005 | FR-001, FR-003 | Medium |
| E2E-044 | Cross-Scenario | SC-014, SC-003 | FR-014, FR-008 | High |
| E2E-045 | Cross-Scenario | SC-009, SC-010 | FR-011, FR-010 | High |
| E2E-046 | Cross-Scenario | SC-013, SC-003 | FR-012, FR-001 | High |

### 10.2 Test Specifications

#### E2E-001: Authorization Code + PKCE Full Flow
- **Category:** Core Journey
- **Scenario:** SC-003
- **Requirements:** FR-001, FR-005, FR-006, FR-009, FR-022
- **Preconditions:** Registered confidential client, registered user, openid+profile scope exists
- **Steps:**
  - Given a registered client with redirect_uri "https://app.example.com/callback" and a user with email "user@example.com"
  - When the client initiates GET /oauth/authorize with response_type=code, client_id, redirect_uri, scope="openid profile", state="xyz", code_challenge=SHA256("verifier123"), code_challenge_method=S256
  - Then the server renders a login page
  - When the user submits email="user@example.com" and password
  - Then the server renders a consent page showing "openid" and "profile" scopes
  - When the user clicks "Approve"
  - Then the server redirects to https://app.example.com/callback?code=<auth_code>&state=xyz
  - When the client sends POST /oauth/token with grant_type=authorization_code, code, redirect_uri, code_verifier="verifier123", client_id, client_secret
  - Then the server returns 200 with access_token (JWT), refresh_token (opaque), id_token (JWT), token_type="Bearer", expires_in=3600
  - And the access_token JWT contains claims: iss, sub=user_id, aud, scope="openid profile", exp, iat, jti
  - And the id_token JWT contains claims: iss, sub=user_id, aud=client_id, exp, iat, auth_time
- **Priority:** Critical

#### E2E-002: Client Credentials Flow
- **Category:** Core Journey
- **Scenario:** SC-004
- **Requirements:** FR-002, FR-005
- **Preconditions:** Registered service client with allowed scopes
- **Steps:**
  - Given a service client with client_id and client_secret, allowed scope "api:read"
  - When the client sends POST /oauth/token with grant_type=client_credentials, client_id, client_secret, scope="api:read"
  - Then the server returns 200 with access_token (JWT), token_type="Bearer", expires_in=3600, scope="api:read"
  - And the response does NOT contain refresh_token
  - And the access_token JWT sub claim equals the client_id
- **Priority:** Critical

#### E2E-003: Device Code Flow
- **Category:** Core Journey
- **Scenario:** SC-005
- **Requirements:** FR-003
- **Preconditions:** Registered client with device_code grant type, registered user
- **Steps:**
  - Given a client configured for device code flow
  - When the device sends POST /oauth/device/authorize with client_id and scope="openid"
  - Then the server returns 200 with device_code, user_code (8 chars), verification_uri, verification_uri_complete, interval=5, expires_in=900
  - When the device polls POST /oauth/token with grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code, client_id
  - Then the server returns 400 with error="authorization_pending"
  - When the user opens verification_uri_complete in a browser
  - Then the server renders login page
  - When the user authenticates and approves consent
  - Then the device's next poll returns 200 with access_token, refresh_token, id_token
- **Priority:** Critical

#### E2E-004: Token Refresh with Rotation
- **Category:** Core Journey
- **Scenario:** SC-006
- **Requirements:** FR-004, FR-006, FR-023
- **Preconditions:** Client has a valid refresh token from a previous authorization
- **Steps:**
  - Given a client with a valid refresh_token "RT-old"
  - When the client sends POST /oauth/token with grant_type=refresh_token, refresh_token="RT-old", client_id, client_secret
  - Then the server returns 200 with a new access_token, a new refresh_token "RT-new" (different from "RT-old"), expires_in
  - And "RT-old" is marked as used
  - When the client uses "RT-new" for another refresh
  - Then the server returns 200 with another new token pair
- **Priority:** Critical

#### E2E-005: Token Introspection (Valid Token)
- **Category:** Core Journey
- **Scenario:** SC-007
- **Requirements:** FR-007
- **Preconditions:** A valid access token exists, a resource server client is registered
- **Steps:**
  - Given a valid access_token issued to user "user@example.com" with scope "openid profile"
  - When the resource server sends POST /oauth/introspect with token=<access_token> and client authentication
  - Then the server returns 200 with active=true, sub=user_id, scope="openid profile", client_id, token_type="access_token", exp, iat, iss
- **Priority:** Critical

#### E2E-006: Token Revocation
- **Category:** Core Journey
- **Scenario:** SC-008
- **Requirements:** FR-008
- **Preconditions:** A valid access token and refresh token exist
- **Steps:**
  - Given a valid refresh_token and its associated access_token
  - When the client sends POST /oauth/revoke with token=<refresh_token>, token_type_hint=refresh_token, client authentication
  - Then the server returns 200 OK
  - When the client introspects the refresh_token
  - Then the server returns active=false
  - When the client introspects the access_token
  - Then the server returns active=false (family revocation)
- **Priority:** Critical

#### E2E-007: OIDC UserInfo Endpoint
- **Category:** Core Journey
- **Scenario:** SC-012
- **Requirements:** FR-009
- **Preconditions:** Valid access token with openid+profile+email scopes
- **Steps:**
  - Given a valid access_token with scope "openid profile email" for user "John Doe" (john@example.com)
  - When the client sends GET /oidc/userinfo with Authorization: Bearer <access_token>
  - Then the server returns 200 with sub=user_id, name="John Doe", email="john@example.com", email_verified=true
- **Priority:** High

#### E2E-008: OIDC Discovery
- **Category:** Core Journey
- **Scenario:** SC-012
- **Requirements:** FR-021
- **Preconditions:** Server is running
- **Steps:**
  - Given the server is running with issuer "https://auth.example.com"
  - When a client sends GET /.well-known/openid-configuration
  - Then the server returns 200 with JSON containing: issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, introspection_endpoint, revocation_endpoint, device_authorization_endpoint, scopes_supported, response_types_supported=["code"], grant_types_supported, token_endpoint_auth_methods_supported, id_token_signing_alg_values_supported=["RS256"]
- **Priority:** High

#### E2E-009: JWKS Endpoint
- **Category:** Core Journey
- **Scenario:** SC-012
- **Requirements:** FR-021
- **Preconditions:** Server is running with configured RSA key pair
- **Steps:**
  - Given the server is running with an RSA signing key
  - When a client sends GET /.well-known/jwks.json
  - Then the server returns 200 with keys array containing at least one RSA public key with: kty="RSA", use="sig", alg="RS256", kid, n, e
- **Priority:** High

#### E2E-010: User Registration
- **Category:** Core Journey
- **Scenario:** SC-002
- **Requirements:** FR-010
- **Preconditions:** No existing user with target email
- **Steps:**
  - Given no user with email "new@example.com" exists
  - When a user sends POST /auth/register with email="new@example.com", password="SecurePass1", name="New User"
  - Then the server returns 201 with id (UUID), email, name, created_at
  - And the response does NOT contain password or password_hash
  - When the user attempts to register again with the same email
  - Then the server returns 409 Conflict
- **Priority:** Critical

#### E2E-011: Client Registration (Admin)
- **Category:** Core Journey
- **Scenario:** SC-001, SC-014
- **Requirements:** FR-014
- **Preconditions:** Admin user is authenticated
- **Steps:**
  - Given an authenticated admin user
  - When the admin sends POST /admin/clients with name="My App", type="confidential", redirect_uris=["https://app.example.com/callback"], allowed_scopes=["openid", "profile"], grant_types=["authorization_code", "refresh_token"]
  - Then the server returns 201 with client_id (UUID), client_secret (random string), and full metadata
  - And the client_secret is only returned once (not retrievable later)
- **Priority:** Critical

#### E2E-012: Social Login via Google
- **Category:** Core Journey
- **Scenario:** SC-009
- **Requirements:** FR-011
- **Preconditions:** Google OIDC is configured, no existing user with Google test email
- **Steps:**
  - Given Google OIDC provider is configured
  - When a user initiates authorization flow and clicks "Sign in with Google"
  - Then the server redirects to Google's authorization endpoint with correct parameters
  - When Google redirects back with a valid authorization code
  - Then the server exchanges the code, validates the ID token, extracts user info
  - And a new user account is created with linked Google account
  - And the authorization flow continues (consent page or token issuance)
- **Priority:** High

#### E2E-013: Social Login via GitHub
- **Category:** Core Journey
- **Scenario:** SC-010
- **Requirements:** FR-011
- **Preconditions:** GitHub OAuth is configured
- **Steps:**
  - Given GitHub OAuth app is configured
  - When a user initiates authorization flow and clicks "Sign in with GitHub"
  - Then the server redirects to GitHub's authorization endpoint
  - When GitHub redirects back with a valid code
  - Then the server exchanges the code, fetches user profile from GitHub API
  - And a new user account is created with linked GitHub account
  - And the authorization flow continues
- **Priority:** High

#### E2E-014: SAML SP Authentication
- **Category:** Core Journey
- **Scenario:** SC-013
- **Requirements:** FR-012
- **Preconditions:** SAML IdP is configured with valid metadata
- **Steps:**
  - Given a SAML IdP is configured (entity_id, SSO URL, certificate)
  - When a user initiates authorization flow and clicks "Sign in with [IdP Name]"
  - Then the server redirects to the SAML IdP's SSO URL with a signed AuthnRequest
  - When the IdP posts a valid SAML Response to the ACS URL
  - Then the server validates the response (signature, conditions, audience)
  - And extracts user attributes (NameID as email, name)
  - And creates or links user account
  - And the authorization flow continues
- **Priority:** High

#### E2E-015: Auth Code Flow with Invalid redirect_uri
- **Category:** Failure
- **Scenario:** SC-003
- **Requirements:** FR-001
- **Preconditions:** Registered client with specific redirect_uris
- **Steps:**
  - Given a client with registered redirect_uri "https://app.example.com/callback"
  - When a request is made to GET /oauth/authorize with redirect_uri="https://evil.example.com/steal"
  - Then the server returns an error page (NOT a redirect) with message indicating invalid redirect_uri
  - And no authorization code is generated
- **Priority:** Critical

#### E2E-016: Auth Code Flow Without PKCE
- **Category:** Failure
- **Scenario:** SC-003
- **Requirements:** FR-022
- **Preconditions:** Registered client
- **Steps:**
  - Given a registered client
  - When a request is made to GET /oauth/authorize without code_challenge parameter
  - Then the server returns 400 Bad Request with error="invalid_request" and description mentioning PKCE requirement
- **Priority:** Critical

#### E2E-017: Authorization Code Replay Attack
- **Category:** Failure
- **Scenario:** SC-003
- **Requirements:** FR-001
- **Preconditions:** A valid authorization code has been exchanged once
- **Steps:**
  - Given a valid authorization code that has been successfully exchanged for tokens
  - When an attacker sends POST /oauth/token with the same authorization code
  - Then the server returns 400 with error="invalid_grant"
  - And all tokens previously issued with this code are revoked
- **Priority:** Critical

#### E2E-018: Refresh Token Reuse Detection
- **Category:** Failure
- **Scenario:** SC-006
- **Requirements:** FR-023
- **Preconditions:** A refresh token has been rotated (used once, new one issued)
- **Steps:**
  - Given refresh_token "RT-1" was used and "RT-2" was issued
  - When an attacker sends POST /oauth/token with grant_type=refresh_token, refresh_token="RT-1"
  - Then the server returns 400 with error="invalid_grant"
  - And ALL tokens in the family are revoked (including "RT-2" and any access tokens)
  - When the legitimate client tries to use "RT-2"
  - Then the server returns 400 with error="invalid_grant"
- **Priority:** Critical

#### E2E-019: Expired Access Token Introspection
- **Category:** Failure
- **Scenario:** SC-007
- **Requirements:** FR-007
- **Preconditions:** An expired access token
- **Steps:**
  - Given an access token that has expired (past exp claim)
  - When a resource server introspects this token
  - Then the server returns 200 with active=false
- **Priority:** High

#### E2E-020: Invalid Client Credentials at Token Endpoint
- **Category:** Failure
- **Scenario:** SC-004
- **Requirements:** FR-002
- **Preconditions:** Registered client
- **Steps:**
  - Given a registered client with client_id="abc"
  - When a request is sent to POST /oauth/token with client_id="abc", client_secret="wrong_secret"
  - Then the server returns 401 Unauthorized with error="invalid_client"
- **Priority:** High

#### E2E-021: Brute Force Login Lockout
- **Category:** Security
- **Scenario:** SC-003
- **Requirements:** FR-017
- **Preconditions:** Registered user with known email
- **Steps:**
  - Given a user with email "user@example.com"
  - When 5 consecutive login attempts are made with wrong passwords
  - Then the 6th attempt returns a lockout message with remaining cooldown time (approximately 30 minutes)
  - And the user cannot log in even with the correct password until lockout expires
  - When an admin sends POST /admin/users/{id}/unlock
  - Then the user can log in again immediately
- **Priority:** Critical

#### E2E-022: Unauthorized Admin API Access
- **Category:** Security
- **Scenario:** SC-014
- **Requirements:** FR-014
- **Preconditions:** Non-admin user is authenticated
- **Steps:**
  - Given an authenticated user with role="user" (not admin)
  - When the user sends POST /admin/clients with client metadata
  - Then the server returns 403 Forbidden
  - When an unauthenticated request is sent to GET /admin/users
  - Then the server returns 401 Unauthorized
- **Priority:** Critical

#### E2E-023: Token Request with Invalid grant_type
- **Category:** Failure
- **Scenario:** SC-004
- **Requirements:** FR-002
- **Preconditions:** Registered client
- **Steps:**
  - Given a registered client
  - When a request is sent to POST /oauth/token with grant_type="password" (removed in OAuth 2.1)
  - Then the server returns 400 with error="unsupported_grant_type"
- **Priority:** High

#### E2E-024: PKCE code_verifier Mismatch
- **Category:** Failure
- **Scenario:** SC-003
- **Requirements:** FR-022
- **Preconditions:** Valid authorization code with PKCE
- **Steps:**
  - Given an authorization code issued with code_challenge=SHA256("correct_verifier")
  - When the client sends POST /oauth/token with code_verifier="wrong_verifier"
  - Then the server returns 400 with error="invalid_grant"
- **Priority:** Critical

#### E2E-025: Device Code Expired Polling
- **Category:** Failure
- **Scenario:** SC-005
- **Requirements:** FR-003
- **Preconditions:** Expired device code
- **Steps:**
  - Given a device code that has expired (past 15-minute window)
  - When the device polls POST /oauth/token with the expired device_code
  - Then the server returns 400 with error="expired_token"
- **Priority:** High

#### E2E-026: Scope Escalation Attempt
- **Category:** Failure
- **Scenario:** SC-004
- **Requirements:** FR-015
- **Preconditions:** Client with limited allowed scopes
- **Steps:**
  - Given a client with allowed_scopes=["api:read"]
  - When the client requests scope="api:read api:write" at the token endpoint
  - Then the server returns 400 with error="invalid_scope" listing the unauthorized scope
- **Priority:** High

#### E2E-027: CSRF Protection on Consent Form
- **Category:** Security
- **Scenario:** SC-003
- **Requirements:** FR-020
- **Preconditions:** User is at consent page
- **Steps:**
  - Given a user is viewing the consent form
  - When an attacker submits the consent form without a valid CSRF token
  - Then the server returns 403 Forbidden
  - And no consent is recorded
- **Priority:** High

#### E2E-028: Revoked Token Introspection
- **Category:** Failure
- **Scenario:** SC-007, SC-008
- **Requirements:** FR-007, FR-008
- **Preconditions:** A token that has been revoked
- **Steps:**
  - Given a valid access token
  - When the token is revoked via POST /oauth/revoke
  - And a resource server introspects the revoked token
  - Then the server returns 200 with active=false
- **Priority:** High

#### E2E-029: Rate Limiting Triggered
- **Category:** Security
- **Scenario:** Cross
- **Requirements:** FR-018
- **Preconditions:** Rate limiter is active
- **Steps:**
  - Given the rate limit for the token endpoint is 30 requests per minute per client
  - When a client sends 31 requests to POST /oauth/token within one minute
  - Then the 31st request returns 429 Too Many Requests
  - And the response includes a Retry-After header
- **Priority:** High

#### E2E-030: Malformed JWT Injection
- **Category:** Security
- **Scenario:** SC-006, SC-007
- **Requirements:** FR-005
- **Preconditions:** Server has known JWKS
- **Steps:**
  - Given the server's JWKS endpoint exposes its public key
  - When an attacker creates a JWT signed with a different key and presents it for introspection
  - Then the server returns active=false
  - When an attacker presents a JWT with "alg":"none"
  - Then the server returns active=false
  - When an attacker presents a truncated/malformed JWT
  - Then the server returns active=false
- **Priority:** High

#### E2E-031: Empty Scope Request
- **Category:** Edge Case
- **Scenario:** SC-003
- **Requirements:** FR-001, FR-009
- **Preconditions:** Client with openid in allowed scopes
- **Steps:**
  - Given a client with allowed scopes including "openid"
  - When an authorization request is made with scope="" (empty)
  - Then the server defaults to scope="openid" and proceeds normally
- **Priority:** Medium

#### E2E-032: Unicode in User Profile Fields
- **Category:** Edge Case
- **Scenario:** SC-002, SC-012
- **Requirements:** FR-010, FR-009
- **Preconditions:** None
- **Steps:**
  - Given a user registers with name="Sebastien Morand" (with accented characters and CJK)
  - When the user's profile is retrieved via UserInfo
  - Then all Unicode characters are preserved correctly
- **Priority:** Medium

#### E2E-033: Very Long redirect_uri
- **Category:** Edge Case
- **Scenario:** SC-003
- **Requirements:** FR-001
- **Preconditions:** Client with long redirect_uri registered
- **Steps:**
  - Given a client registered with a redirect_uri of 2048 characters
  - When an authorization request is made with the full URI
  - Then the server handles it correctly (exact match comparison works)
  - When a URI of 2049+ characters is submitted for registration
  - Then the server rejects it with 400 (URI too long)
- **Priority:** Medium

#### E2E-034: Concurrent Auth Code Requests
- **Category:** Edge Case
- **Scenario:** SC-003
- **Requirements:** FR-001
- **Preconditions:** Registered client, authenticated user
- **Steps:**
  - Given a user has two browser tabs open
  - When both tabs initiate authorization requests simultaneously for the same client
  - Then each gets a unique authorization code
  - And each code can be exchanged independently
  - And the second exchange does not invalidate the first token set
- **Priority:** Medium

#### E2E-035: Client with No Allowed Scopes
- **Category:** Edge Case
- **Scenario:** SC-004
- **Requirements:** FR-002, FR-015
- **Preconditions:** Service client with empty allowed_scopes
- **Steps:**
  - Given a service client with allowed_scopes=[]
  - When the client requests any scope at the token endpoint
  - Then the server returns 400 with error="invalid_scope"
  - When the client requests with no scope parameter
  - Then the server returns 400 with error="invalid_scope" (no default available)
- **Priority:** Medium

#### E2E-036: Token Refresh at Exact Expiry Boundary
- **Category:** Edge Case
- **Scenario:** SC-006
- **Requirements:** FR-004
- **Preconditions:** Refresh token near expiry
- **Steps:**
  - Given a refresh token that expires in the next second
  - When the client sends a refresh request at the exact expiry moment
  - Then the server either issues new tokens (if token was valid at request time) or returns error="invalid_grant" (if expired)
  - And the behavior is deterministic (no partial state)
- **Priority:** Medium

#### E2E-037: Multiple Consent Grants for Same Client (Idempotent)
- **Category:** Edge Case
- **Scenario:** SC-003, SC-011
- **Requirements:** FR-016
- **Preconditions:** User has existing consent for a client
- **Steps:**
  - Given a user has granted consent to "My App" for scopes "openid profile"
  - When the user goes through the authorization flow again for "My App" with scope="openid profile"
  - Then the consent screen is skipped (existing consent covers requested scopes)
  - When the user goes through with scope="openid profile email" (broader)
  - Then the consent screen shows only the new scope "email"
- **Priority:** Medium

#### E2E-038: Device Code Slow Polling
- **Category:** Edge Case
- **Scenario:** SC-005
- **Requirements:** FR-003
- **Preconditions:** Active device code flow
- **Steps:**
  - Given an active device code with interval=5 seconds
  - When the device polls after only 2 seconds
  - Then the server returns 400 with error="slow_down"
  - And the new interval is increased by 5 seconds (now 10)
  - When the device waits 10 seconds and polls again
  - Then the server returns error="authorization_pending" (normal response)
- **Priority:** Medium

#### E2E-039: JWKS Key Rotation
- **Category:** Edge Case
- **Scenario:** SC-007
- **Requirements:** FR-005, FR-021
- **Preconditions:** Tokens issued with old key, new key is active
- **Steps:**
  - Given tokens were issued with signing key "kid-1"
  - When the server rotates to a new signing key "kid-2"
  - Then GET /.well-known/jwks.json returns both keys
  - And tokens signed with "kid-1" are still valid for introspection
  - And new tokens are signed with "kid-2"
- **Priority:** Medium

#### E2E-040: Storage Backend Compatibility
- **Category:** Edge Case
- **Scenario:** Cross
- **Requirements:** FR-013
- **Preconditions:** Data exists in JSON backend
- **Steps:**
  - Given users and clients created with JSON backend
  - When the same test suite runs against Firestore backend
  - Then all operations produce identical results
  - And data integrity is maintained across both backends
- **Priority:** Medium

#### E2E-041: Consent Revocation Cascades Token Revocation
- **Category:** Edge Case
- **Scenario:** SC-011
- **Requirements:** FR-016, FR-008
- **Preconditions:** User has active consent with tokens
- **Steps:**
  - Given a user has granted consent to "My App" and has active access+refresh tokens
  - When the user revokes consent via DELETE /auth/consents/{id}
  - Then the consent record is marked as revoked
  - And all access tokens for this user+client are invalidated
  - And all refresh tokens for this user+client are revoked
  - When the client attempts to use the old access token
  - Then introspection returns active=false
- **Priority:** High

#### E2E-042: Admin Creates Client with Duplicate Name
- **Category:** Edge Case
- **Scenario:** SC-001, SC-014
- **Requirements:** FR-014
- **Preconditions:** Client with name "My App" already exists
- **Steps:**
  - Given a client named "My App" exists
  - When the admin creates another client with name="My App"
  - Then the server returns 409 Conflict with message about duplicate name
- **Priority:** Medium

#### E2E-043: User Mid-Consent Triggers Device Code Flow
- **Category:** Cross-Scenario
- **Scenario:** SC-003, SC-005
- **Requirements:** FR-001, FR-003
- **Preconditions:** User has two pending flows
- **Steps:**
  - Given a user is on the consent page for a web app (authorization code flow)
  - When the same user opens a new tab to approve a device code
  - Then both flows can be completed independently
  - And each produces its own token set
  - And the consent records are separate
- **Priority:** Medium

#### E2E-044: Admin Revokes Client While User Has Active Session
- **Category:** Cross-Scenario
- **Scenario:** SC-014, SC-003
- **Requirements:** FR-014, FR-008
- **Preconditions:** User has active tokens from a client
- **Steps:**
  - Given a user has active access and refresh tokens for client "My App"
  - When an admin deactivates "My App" via DELETE /admin/clients/{id}
  - Then all tokens for "My App" are revoked
  - And introspection of those tokens returns active=false
  - And new authorization requests for "My App" are rejected
- **Priority:** High

#### E2E-045: Social Login Links to Existing Local Account
- **Category:** Cross-Scenario
- **Scenario:** SC-009, SC-010
- **Requirements:** FR-011, FR-010
- **Preconditions:** User registered with email+password
- **Steps:**
  - Given a user registered with email="user@example.com" and password
  - When the user authenticates via Google using the same email
  - Then the Google account is linked to the existing user (no duplicate)
  - And the user can still log in with password
  - And the user can log in with Google
  - When the user also links GitHub (same email)
  - Then all three methods work for the same account
- **Priority:** High

#### E2E-046: SAML Auth Creates User Then OAuth Token Issued
- **Category:** Cross-Scenario
- **Scenario:** SC-013, SC-003
- **Requirements:** FR-012, FR-001
- **Preconditions:** SAML IdP configured, no existing user
- **Steps:**
  - Given a SAML IdP is configured and no user exists with the SAML NameID email
  - When a user authenticates via SAML during an authorization code flow
  - Then a new user account is created with SAML-provided attributes
  - And the authorization flow completes (consent, code, tokens)
  - And the issued tokens have correct user claims
  - And the user appears in the admin user list with linked SAML account
- **Priority:** High

## 11. Open Questions & TBDs

- **Email verification:** Should user registration require email verification before the account can be used in OAuth flows? (Currently not specified.)
- **Password reset:** Should there be a built-in password reset flow (forgot password)? (Currently not in scope.)
- **Session management:** How long should the login session last between the user authenticating and being redirected? (Currently implicit, no explicit session timeout defined.)
- **Key storage:** Where should the RSA private key be stored? File path via env var, or inline env var, or key management service?
- **SAML SP metadata endpoint:** Should the server expose its own SAML SP metadata for easy IdP configuration?
- **Token size limits:** Maximum claims in JWT before recommending opaque tokens?
- **Firestore collection naming:** Convention for Firestore collections (e.g., oauth2_users, oauth2_clients)?

## 12. Glossary

| Term | Definition |
|------|-----------|
| **OAuth 2.1** | The upcoming consolidation of OAuth 2.0, requiring PKCE, forbidding implicit grant and password grant |
| **PKCE** | Proof Key for Code Exchange: a mechanism to prevent authorization code interception attacks |
| **OIDC** | OpenID Connect: an identity layer on top of OAuth 2.0 for user authentication |
| **JWT** | JSON Web Token: a compact, URL-safe token format with signed claims |
| **JWKS** | JSON Web Key Set: a set of public keys used to verify JWT signatures |
| **RS256** | RSA Signature with SHA-256: an asymmetric signing algorithm for JWTs |
| **Argon2id** | A memory-hard password hashing algorithm (hybrid of Argon2i and Argon2d) |
| **Opaque token** | A random token string with no embedded information (must be looked up server-side) |
| **Token family** | A chain of refresh tokens linked by a family ID for reuse detection |
| **SAML SP** | SAML Service Provider: an application that delegates authentication to a SAML IdP |
| **SAML IdP** | SAML Identity Provider: a service that authenticates users and issues SAML assertions |
| **ACS** | Assertion Consumer Service: the endpoint that receives SAML responses |
| **Consent** | A user's explicit approval for a client to access specific scopes on their behalf |
| **Introspection** | An endpoint where resource servers can check if a token is active and get its metadata |
| **Device code flow** | An OAuth grant for devices with limited input, where users authorize on a separate device |
