"""OAuth2 authorization and token endpoints."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from config import Settings
from dependencies import AppDependencies
from models.schemas import ErrorResponse
from services.auth_code_service import AuthCodeError
from services.client_service import ClientServiceError
from services.device_code_service import DeviceCodeError
from services.scope_service import ScopeServiceError
from services.token_service import TokenServiceError

logger = logging.getLogger(__name__)


def create_oauth_router(deps: AppDependencies, settings: Settings) -> APIRouter:  # noqa: PLR0915
    """Create OAuth2 router."""
    router = APIRouter(prefix="/oauth", tags=["oauth"])

    @router.get("/authorize")
    async def authorize(  # noqa: PLR0911
        request: Request,
        response_type: str = Query(...),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query(default=""),
        state: str = Query(default=""),
        code_challenge: str = Query(default=""),
        code_challenge_method: str = Query(default="S256"),
        nonce: str = Query(default=""),
    ) -> HTMLResponse | RedirectResponse | JSONResponse:
        if response_type != "code":
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    error="unsupported_response_type", error_description="Only 'code' is supported"
                ).model_dump(),
            )

        client = await deps.client_service.get_client(client_id)
        if not client:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(error="invalid_request", error_description="Unknown client_id").model_dump(),
            )

        if redirect_uri not in client.redirect_uris:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "Invalid redirect_uri",
                    "description": "The redirect URI does not match any registered URIs for this client.",
                },
                status_code=400,
            )

        if not code_challenge:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    error="invalid_request", error_description="PKCE required per OAuth 2.1. Missing code_challenge."
                ).model_dump(),
            )

        if code_challenge_method != "S256":
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    error="invalid_request", error_description="Only S256 code_challenge_method is supported"
                ).model_dump(),
            )

        if "authorization_code" not in client.grant_types:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    error="unauthorized_client", error_description="Client not authorized for authorization_code grant"
                ).model_dump(),
            )

        try:
            requested_scopes = await deps.scope_service.validate_scopes(scope or "openid", client.allowed_scopes)
        except ScopeServiceError as exc:
            params = urlencode({"error": "invalid_scope", "error_description": str(exc), "state": state})
            return RedirectResponse(url=f"{redirect_uri}?{params}", status_code=302)

        scope_str = " ".join(requested_scopes)

        request.session["oauth_params"] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope_str,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "nonce": nonce,
        }

        templates = request.app.state.templates
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "client_name": client.name,
                "scope": scope_str,
                "google_enabled": settings.google_enabled,
                "github_enabled": settings.github_enabled,
                "saml_idps": [],
            },
        )

    @router.post("/authorize/login")
    async def authorize_login(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
    ) -> HTMLResponse | RedirectResponse:
        oauth_params = getattr(request, "session", {}).get("oauth_params")
        if not oauth_params:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "Session expired",
                    "description": "Please restart the authorization flow.",
                },
                status_code=400,
            )

        ip = request.client.host if request.client else ""
        try:
            user = await deps.user_service.authenticate(email, password, ip)
        except Exception as exc:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "client_name": "",
                    "scope": oauth_params.get("scope", ""),
                    "error": str(exc),
                    "email": email,
                    "google_enabled": settings.google_enabled,
                    "github_enabled": settings.github_enabled,
                    "saml_idps": [],
                },
            )

        request.session["user_id"] = user.id
        request.session["auth_time"] = int(user.updated_at.timestamp())

        scopes = oauth_params["scope"].split()
        has_consent = await deps.consent_service.check_existing_consent(user.id, oauth_params["client_id"], scopes)

        if has_consent:
            return await _issue_auth_code(deps, request, oauth_params, user.id)

        client = await deps.client_service.get_client(oauth_params["client_id"])
        client_name = client.name if client else "Unknown"
        missing_scopes = await deps.consent_service.get_missing_scopes(user.id, oauth_params["client_id"], scopes)

        scope_descriptions = await deps.scope_service.list_scopes()
        scope_map = {s.name: s.description for s in scope_descriptions}

        templates = request.app.state.templates
        return templates.TemplateResponse(
            "consent.html",
            {
                "request": request,
                "client_name": client_name,
                "scopes": [(s, scope_map.get(s, s)) for s in missing_scopes],
            },
        )

    @router.post("/authorize/consent")
    async def authorize_consent(
        request: Request,
        action: str = Form(...),
    ) -> RedirectResponse:
        oauth_params = getattr(request, "session", {}).get("oauth_params")
        user_id = getattr(request, "session", {}).get("user_id")

        if not oauth_params or not user_id:
            return RedirectResponse(url="/", status_code=302)

        redirect_uri = oauth_params["redirect_uri"]
        state = oauth_params.get("state", "")

        if action == "deny":
            params = urlencode({"error": "access_denied", "state": state})
            return RedirectResponse(url=f"{redirect_uri}?{params}", status_code=302)

        scopes = oauth_params["scope"].split()
        await deps.consent_service.grant_consent(user_id, oauth_params["client_id"], scopes)

        return await _issue_auth_code(deps, request, oauth_params, user_id)

    @router.get("/authorize/consent-check")
    async def authorize_consent_check(
        request: Request,
    ) -> HTMLResponse | RedirectResponse:
        """Check consent after social/SAML login and issue code or show consent page."""
        oauth_params = getattr(request, "session", {}).get("oauth_params")
        user_id = getattr(request, "session", {}).get("user_id")

        if not oauth_params or not user_id:
            return RedirectResponse(url="/", status_code=302)

        scopes = oauth_params["scope"].split()
        has_consent = await deps.consent_service.check_existing_consent(user_id, oauth_params["client_id"], scopes)

        if has_consent:
            return await _issue_auth_code(deps, request, oauth_params, user_id)

        client = await deps.client_service.get_client(oauth_params["client_id"])
        client_name = client.name if client else "Unknown"
        missing_scopes = await deps.consent_service.get_missing_scopes(user_id, oauth_params["client_id"], scopes)

        scope_descriptions = await deps.scope_service.list_scopes()
        scope_map = {s.name: s.description for s in scope_descriptions}

        templates = request.app.state.templates
        return templates.TemplateResponse(
            "consent.html",
            {
                "request": request,
                "client_name": client_name,
                "scopes": [(s, scope_map.get(s, s)) for s in missing_scopes],
            },
        )

    @router.post("/token")
    async def token_endpoint(
        grant_type: str = Form(...),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
        refresh_token: str = Form(default=""),
        scope: str = Form(default=""),
        device_code: str = Form(default=""),
    ) -> JSONResponse:
        if grant_type == "authorization_code":
            return await _handle_auth_code_grant(deps, code, redirect_uri, client_id, client_secret, code_verifier)

        if grant_type == "client_credentials":
            return await _handle_client_credentials_grant(deps, client_id, client_secret, scope)

        if grant_type == "refresh_token":
            return await _handle_refresh_grant(deps, refresh_token, client_id, client_secret)

        if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return await _handle_device_code_grant(deps, device_code, client_id)

        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                error="unsupported_grant_type", error_description=f"Grant type '{grant_type}' is not supported"
            ).model_dump(),
        )

    @router.post("/introspect")
    async def introspect_endpoint(
        token: str = Form(...),
        token_type_hint: str = Form(default=""),  # noqa: ARG001
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
    ) -> JSONResponse:
        try:
            await deps.client_service.authenticate_client(client_id, client_secret)
        except ClientServiceError:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})

        result = await deps.token_service.introspect(token, client_id)
        return JSONResponse(content=result)

    @router.post("/revoke")
    async def revoke_endpoint(
        token: str = Form(...),
        token_type_hint: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
    ) -> JSONResponse:
        try:
            await deps.client_service.authenticate_client(client_id, client_secret)
        except ClientServiceError:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})

        await deps.token_service.revoke(token, token_type_hint, client_id)
        return JSONResponse(content={}, status_code=200)

    @router.post("/device/authorize")
    async def device_authorize(
        client_id: str = Form(...),
        scope: str = Form(default=""),
    ) -> JSONResponse:
        client = await deps.client_service.get_client(client_id)
        if not client:
            return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_client").model_dump())

        if "urn:ietf:params:oauth:grant-type:device_code" not in client.grant_types:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    error="unauthorized_client", error_description="Client not authorized for device_code grant"
                ).model_dump(),
            )

        try:
            requested_scopes = await deps.scope_service.validate_scopes(scope or "openid", client.allowed_scopes)
        except ScopeServiceError as exc:
            return JSONResponse(
                status_code=400, content=ErrorResponse(error="invalid_scope", error_description=str(exc)).model_dump()
            )

        verification_uri = f"{settings.issuer_url}/device"
        result = await deps.device_code_service.create_device_code(
            client_id=client_id,
            scope=" ".join(requested_scopes),
            verification_uri=verification_uri,
        )
        return JSONResponse(content=result)

    @router.get("/device")
    async def device_verify_page(
        request: Request,
        user_code: str = Query(default=""),
    ) -> HTMLResponse:
        templates = request.app.state.templates
        return templates.TemplateResponse(
            "device_verify.html",
            {"request": request, "user_code": user_code, "error": ""},
        )

    @router.post("/device/verify")
    async def device_verify_submit(
        request: Request,
        user_code: str = Form(...),
    ) -> HTMLResponse | RedirectResponse:
        device_code = await deps.device_code_service.verify_user_code(user_code)
        if not device_code:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "device_verify.html",
                {"request": request, "user_code": user_code, "error": "Invalid or expired user code"},
            )

        request.session["device_user_code"] = user_code
        templates = request.app.state.templates
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "client_name": "Device",
                "scope": device_code.scope,
                "google_enabled": settings.google_enabled,
                "github_enabled": settings.github_enabled,
                "saml_idps": [],
                "device_flow": True,
            },
        )

    return router


async def _issue_auth_code(
    deps: AppDependencies,
    _request: Request,
    oauth_params: dict[str, str],
    user_id: str,
) -> RedirectResponse:
    """Issue an authorization code and redirect."""
    code = await deps.auth_code_service.create_code(
        client_id=oauth_params["client_id"],
        user_id=user_id,
        redirect_uri=oauth_params["redirect_uri"],
        scope=oauth_params["scope"],
        code_challenge=oauth_params["code_challenge"],
        code_challenge_method=oauth_params.get("code_challenge_method", "S256"),
        nonce=oauth_params.get("nonce", ""),
    )

    params = {"code": code, "state": oauth_params.get("state", "")}
    redirect_uri = oauth_params["redirect_uri"]
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


async def _handle_auth_code_grant(
    deps: AppDependencies,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
) -> JSONResponse:
    """Handle authorization_code grant type."""
    try:
        client = await deps.client_service.authenticate_client(client_id, client_secret)
    except ClientServiceError as exc:
        return JSONResponse(
            status_code=exc.code, content=ErrorResponse(error="invalid_client", error_description=str(exc)).model_dump()
        )

    try:
        auth_code = await deps.auth_code_service.exchange_code(code, client_id, redirect_uri, code_verifier)
    except AuthCodeError as exc:
        return JSONResponse(
            status_code=exc.code, content=ErrorResponse(error=exc.error_code, error_description=str(exc)).model_dump()
        )

    user = await deps.user_service.get_user(auth_code.user_id)
    if not user:
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(error="invalid_grant", error_description="User not found").model_dump(),
        )

    tokens = await deps.token_service.issue_tokens(
        user=user,
        client=client,
        scope=auth_code.scope,
        nonce=auth_code.nonce,
    )
    return JSONResponse(content=tokens)


async def _handle_client_credentials_grant(
    deps: AppDependencies,
    client_id: str,
    client_secret: str,
    scope: str,
) -> JSONResponse:
    """Handle client_credentials grant type."""
    try:
        client = await deps.client_service.authenticate_client(client_id, client_secret)
    except ClientServiceError as exc:
        return JSONResponse(
            status_code=exc.code, content=ErrorResponse(error="invalid_client", error_description=str(exc)).model_dump()
        )

    if client.type.value != "service":
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                error="unauthorized_client", error_description="Only service clients can use client_credentials"
            ).model_dump(),
        )

    try:
        requested_scopes = await deps.scope_service.validate_scopes(scope, client.allowed_scopes)
    except ScopeServiceError as exc:
        return JSONResponse(
            status_code=400, content=ErrorResponse(error="invalid_scope", error_description=str(exc)).model_dump()
        )

    tokens = await deps.token_service.issue_client_credentials_token(client, " ".join(requested_scopes))
    return JSONResponse(content=tokens)


async def _handle_refresh_grant(
    deps: AppDependencies,
    refresh_token: str,
    client_id: str,
    client_secret: str,
) -> JSONResponse:
    """Handle refresh_token grant type."""
    try:
        await deps.client_service.authenticate_client(client_id, client_secret)
    except ClientServiceError as exc:
        return JSONResponse(
            status_code=exc.code, content=ErrorResponse(error="invalid_client", error_description=str(exc)).model_dump()
        )

    try:
        tokens = await deps.token_service.refresh_tokens(refresh_token, client_id)
    except TokenServiceError as exc:
        return JSONResponse(
            status_code=exc.code, content=ErrorResponse(error=exc.error_code, error_description=str(exc)).model_dump()
        )

    return JSONResponse(content=tokens)


async def _handle_device_code_grant(
    deps: AppDependencies,
    device_code: str,
    client_id: str,
) -> JSONResponse:
    """Handle device_code grant type."""
    try:
        stored = await deps.device_code_service.poll_device_code(device_code, client_id)
    except DeviceCodeError as exc:
        return JSONResponse(
            status_code=400, content=ErrorResponse(error=exc.error_code, error_description=str(exc)).model_dump()
        )

    user = await deps.user_service.get_user(stored.user_id)
    if not user:
        return JSONResponse(status_code=400, content=ErrorResponse(error="server_error").model_dump())

    client = await deps.client_service.get_client(client_id)
    if not client:
        return JSONResponse(status_code=400, content=ErrorResponse(error="invalid_client").model_dump())

    tokens = await deps.token_service.issue_tokens(user=user, client=client, scope=stored.scope)
    return JSONResponse(content=tokens)
