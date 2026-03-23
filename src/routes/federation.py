"""Federation endpoints for social login (Google, GitHub) and SAML SP."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from config import Settings
from dependencies import AppDependencies
from models.user import User
from services.saml_service import SAMLError
from services.social_service import SocialLoginError

logger = logging.getLogger(__name__)


def create_federation_router(deps: AppDependencies, _settings: Settings) -> APIRouter:
    """Create federation router for social login and SAML."""
    router = APIRouter(prefix="/federation", tags=["federation"])

    # --- Google OIDC ---

    @router.get("/google/start")
    async def google_start(request: Request) -> RedirectResponse:
        """Redirect to Google for authentication."""
        state = deps.social_service.generate_state()
        nonce = secrets.token_urlsafe(16)
        request.session["social_state"] = state
        request.session["social_nonce"] = nonce
        url = deps.social_service.get_google_auth_url(state, nonce)
        return RedirectResponse(url=url, status_code=302)

    @router.get("/google/callback")
    async def google_callback(
        request: Request,
        code: str = Query(default=""),
        state: str = Query(default=""),
        error: str = Query(default=""),
    ) -> HTMLResponse | RedirectResponse:
        """Handle Google OAuth callback."""
        templates = request.app.state.templates
        if error:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Google login failed", "description": error},
                status_code=400,
            )

        expected_state = request.session.pop("social_state", "")
        expected_nonce = request.session.pop("social_nonce", "")

        if not state or state != expected_state:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "Invalid state",
                    "description": "CSRF validation failed. Please try again.",
                },
                status_code=400,
            )

        try:
            user = await deps.social_service.handle_google_callback(code, expected_nonce)
        except SocialLoginError as exc:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Google login failed", "description": str(exc)},
                status_code=400,
            )

        return _complete_social_login(request, user)

    # --- GitHub OAuth ---

    @router.get("/github/start")
    async def github_start(request: Request) -> RedirectResponse:
        """Redirect to GitHub for authentication."""
        state = deps.social_service.generate_state()
        request.session["social_state"] = state
        url = deps.social_service.get_github_auth_url(state)
        return RedirectResponse(url=url, status_code=302)

    @router.get("/github/callback")
    async def github_callback(
        request: Request,
        code: str = Query(default=""),
        state: str = Query(default=""),
        error: str = Query(default=""),
    ) -> HTMLResponse | RedirectResponse:
        """Handle GitHub OAuth callback."""
        templates = request.app.state.templates
        if error:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "GitHub login failed", "description": error},
                status_code=400,
            )

        expected_state = request.session.pop("social_state", "")

        if not state or not deps.social_service.verify_github_state(state, expected_state):
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "Invalid state",
                    "description": "CSRF validation failed. Please try again.",
                },
                status_code=400,
            )

        try:
            user = await deps.social_service.handle_github_callback(code)
        except SocialLoginError as exc:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "GitHub login failed", "description": str(exc)},
                status_code=400,
            )

        return _complete_social_login(request, user)

    # --- SAML SP ---

    @router.get("/saml/{idp_id}/start")
    async def saml_start(request: Request, idp_id: str) -> HTMLResponse | RedirectResponse:
        """Redirect to SAML IdP for authentication."""
        templates = request.app.state.templates
        idp = await deps.saml_service.get_idp(idp_id)
        if not idp:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Unknown IdP", "description": "SAML Identity Provider not found."},
                status_code=404,
            )

        relay_state = deps.saml_service.generate_relay_state()
        request.session["saml_relay_state"] = relay_state
        request.session["saml_idp_id"] = idp_id
        url = deps.saml_service.generate_authn_request_redirect(idp, relay_state)
        return RedirectResponse(url=url, status_code=302)

    @router.post("/saml/acs")
    async def saml_acs(
        request: Request,
        SAMLResponse: str = Form(...),
        RelayState: str = Form(default=""),
    ) -> HTMLResponse | RedirectResponse:
        """SAML Assertion Consumer Service endpoint."""
        templates = request.app.state.templates
        expected_relay = request.session.pop("saml_relay_state", "")

        if RelayState != expected_relay:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Invalid relay state", "description": "SAML CSRF validation failed."},
                status_code=400,
            )

        try:
            user = await deps.saml_service.handle_saml_response(SAMLResponse, RelayState)
        except SAMLError as exc:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "SAML authentication failed", "description": str(exc)},
                status_code=400,
            )

        return _complete_social_login(request, user)

    return router


def _complete_social_login(request: Request, user: User) -> RedirectResponse:
    """Set session data after social/SAML login and redirect to consent or issue code."""
    request.session["user_id"] = user.id
    request.session["auth_time"] = int(datetime.now(tz=UTC).timestamp())

    oauth_params = request.session.get("oauth_params")
    device_user_code = request.session.get("device_user_code")

    if oauth_params:
        return RedirectResponse(url="/oauth/authorize/consent-check", status_code=302)

    if device_user_code:
        return RedirectResponse(url="/federation/device-approve", status_code=302)

    return RedirectResponse(url="/", status_code=302)
