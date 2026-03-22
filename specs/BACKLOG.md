# OAuth2 Backlog

## Features to Implement (Covered by Spec)

All items below are covered by the specification `2026-03-22_23:58:11-oauth2-authorization-server.md`:

### Authentication
- [ ] OAuth2 authorization code flow (FR-001)
- [ ] OAuth2 client credentials flow (FR-002)
- [ ] OAuth2 device code flow (FR-003)
- [ ] Token endpoint implementation (FR-001, FR-002, FR-003, FR-004)
- [ ] Authorization endpoint implementation (FR-001)

### Token Management
- [ ] Access token generation (JWT) (FR-005)
- [ ] Refresh token handling (FR-004, FR-006)
- [ ] Token introspection (FR-007)
- [ ] Token revocation (FR-008)

### Client Management
- [ ] Client registration (FR-014)
- [ ] Client authentication (FR-014)
- [ ] Client credentials management (FR-014)

### Security
- [ ] PKCE support (FR-022)
- [ ] Scope validation (FR-015)
- [ ] Rate limiting (FR-018)
- [ ] Audit logging (FR-019)

### Integration
- [ ] OpenID Connect support (FR-009, FR-021)
- [ ] SAML integration (FR-012)
- [ ] Social login providers (FR-011)

## Deferred Ideas

### BL-001: Email Verification
- **Description:** Require email verification (via confirmation link) before allowing user accounts to participate in OAuth flows.
- **Rationale:** Not essential for MVP; can be added as an enhancement.
- **Source:** Spec open questions (2026-03-22_23:58:11-oauth2-authorization-server.md)

### BL-002: Password Reset Flow
- **Description:** Built-in "forgot password" flow with email-based reset tokens.
- **Rationale:** Important for production but not required for initial OAuth2 functionality.
- **Source:** Spec open questions (2026-03-22_23:58:11-oauth2-authorization-server.md)

### BL-003: MFA (Multi-Factor Authentication)
- **Description:** SMS or email-based multi-factor authentication for user login.
- **Rationale:** Deferred from scope; listed as non-goal in spec.
- **Source:** Spec non-goals (2026-03-22_23:58:11-oauth2-authorization-server.md)

### BL-004: WebAuthn / Passkeys
- **Description:** FIDO2/WebAuthn passwordless authentication support.
- **Rationale:** Modern auth mechanism, but adds significant complexity to MVP.
- **Source:** Spec non-goals (2026-03-22_23:58:11-oauth2-authorization-server.md)

### BL-005: Additional Social Providers (Microsoft, Apple, etc.)
- **Description:** Extend social login beyond Google and GitHub to include Microsoft, Apple, and other OIDC providers.
- **Rationale:** Google + GitHub covers most use cases for MVP.
- **Source:** Interview discussion

### BL-006: SAML IdP Capability
- **Description:** Act as a SAML Identity Provider (issue SAML assertions for legacy consumers), in addition to the current SAML SP role.
- **Rationale:** SP covers the primary use case (corporate IdP federation); IdP adds complexity.
- **Source:** Interview discussion (user chose SAML SP only)
