"""Server-rendered SOC analyst dashboard."""

from __future__ import annotations

import secrets
from collections import Counter
from datetime import datetime, timezone
from hmac import compare_digest
from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Form,
    Request,
    status,
)
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

from src.cases.models import ALLOWED_CASE_STATUSES


router = APIRouter(
    include_in_schema=False
)

TEMPLATE_DIRECTORY = (
    Path(__file__).resolve().parent
    / "templates"
)

templates = Jinja2Templates(
    directory=str(TEMPLATE_DIRECTORY)
)

OPEN_CASE_STATUSES = {
    "new",
    "triage",
    "investigating",
    "contained",
}


def _format_timestamp(value: object) -> str:
    """Format an ISO timestamp for analyst display."""

    if not isinstance(value, str) or not value.strip():
        return "Unknown"

    timestamp = value.strip()

    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return value

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    parsed = parsed.astimezone(
        timezone.utc
    )

    return parsed.strftime(
        "%b %d, %Y %I:%M %p UTC"
    )


templates.env.filters[
    "soc_datetime"
] = _format_timestamp


def _current_account(request: Request):
    """Return the active analyst stored in the session."""

    user_id = request.session.get("user_id")

    if not isinstance(user_id, str) or not user_id:
        return None

    account = (
        request.app.state.identity_store
        .get_by_id(user_id)
    )

    if account is None or not account.is_active:
        request.session.clear()
        return None

    return account


def _authenticated(
    request: Request,
) -> bool:
    """Return whether an active analyst is signed in."""

    return _current_account(request) is not None


def _csrf_token(
    request: Request,
) -> str:
    """Return or create the session CSRF token."""

    token = request.session.get(
        "csrf_token"
    )

    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token

    return token


def _valid_csrf_token(
    request: Request,
    supplied_token: str,
) -> bool:
    """Validate a form token against the session token."""

    expected_token = request.session.get(
        "csrf_token"
    )

    if (
        not isinstance(expected_token, str)
        or not expected_token
        or not isinstance(supplied_token, str)
        or not supplied_token
    ):
        return False

    return compare_digest(
        supplied_token.encode("utf-8"),
        expected_token.encode("utf-8"),
    )


def _login_redirect() -> RedirectResponse:
    """Redirect an unauthenticated browser to login."""

    return RedirectResponse(
        url="/dashboard/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _csrf_failure() -> HTMLResponse:
    """Return a CSRF validation failure."""

    return HTMLResponse(
        content=(
            "<h1>Forbidden</h1>"
            "<p>Invalid or expired form token.</p>"
        ),
        status_code=status.HTTP_403_FORBIDDEN,
    )


@router.get("/")
def root() -> Response:
    """Redirect the root URL to the dashboard."""

    return RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/dashboard/login",
    response_class=HTMLResponse,
)
def dashboard_login_page(
    request: Request,
) -> Response:
    """Display the analyst login form."""

    if _authenticated(request):
        return RedirectResponse(
            url="/dashboard",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return templates.TemplateResponse(
        request=request,
        name="dashboard/login.html",
        context={
            "error": None,
            "csrf_token": _csrf_token(request),
        },
    )


@router.post(
    "/dashboard/login",
    response_class=HTMLResponse,
)
def dashboard_login(
    request: Request,
    email: Annotated[
        str,
        Form(min_length=3),
    ],
    password: Annotated[
        str,
        Form(min_length=1),
    ],
    csrf_token: Annotated[
        str,
        Form(min_length=1),
    ],
) -> Response:
    """Authenticate an individual SOC analyst."""

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    account = (
        request.app.state.identity_store
        .authenticate(
            email=email,
            password=password,
        )
    )

    if account is None:
        return templates.TemplateResponse(
            request=request,
            name="dashboard/login.html",
            context={
                "error": "Invalid email or password.",
                "csrf_token": _csrf_token(request),
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    request.session.clear()
    request.session["authenticated"] = True
    request.session["user_id"] = account.user_id
    request.session["csrf_token"] = (
        secrets.token_urlsafe(32)
    )

    return RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/dashboard/logout")
def dashboard_logout(
    request: Request,
    csrf_token: Annotated[
        str,
        Form(min_length=1),
    ],
) -> Response:
    """Clear the authenticated browser session."""

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    request.session.clear()

    return RedirectResponse(
        url="/dashboard/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard_home(
    request: Request,
    case_status: str | None = None,
) -> Response:
    """Display metrics and the analyst case queue."""

    if not _authenticated(request):
        return _login_redirect()

    store = request.app.state.case_store

    normalized_status = (
        case_status.strip().lower()
        if isinstance(case_status, str)
        and case_status.strip()
        else None
    )

    if normalized_status not in (
        ALLOWED_CASE_STATUSES
    ):
        normalized_status = None

    cases = store.list_cases(
        status=normalized_status,
        limit=500,
    )

    all_cases = store.list_cases(
        limit=500
    )

    status_counts = Counter(
        case.status
        for case in all_cases
    )

    metrics = {
        "total": len(all_cases),
        "open": sum(
            1
            for case in all_cases
            if case.status in OPEN_CASE_STATUSES
        ),
        "p1": sum(
            1
            for case in all_cases
            if (
                case.priority == "P1"
                and case.status
                in OPEN_CASE_STATUSES
            )
        ),
        "unassigned": sum(
            1
            for case in all_cases
            if (
                case.assigned_to is None
                and case.status
                in OPEN_CASE_STATUSES
            )
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard/index.html",
        context={
            "cases": cases,
            "metrics": metrics,
            "status_counts": status_counts,
            "selected_status": normalized_status,
            "csrf_token": _csrf_token(request),
        },
    )


@router.get(
    "/dashboard/cases/{case_id}",
    response_class=HTMLResponse,
)
def dashboard_case_detail(
    request: Request,
    case_id: str,
) -> Response:
    """Display complete details for one SOC case."""

    if not _authenticated(request):
        return _login_redirect()

    store = request.app.state.case_store

    case = store.get_case(case_id)

    if case is None:
        return templates.TemplateResponse(
            request=request,
            name="dashboard/not_found.html",
            context={
                "case_id": case_id,
                "csrf_token": _csrf_token(
                    request
                ),
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )

    audit_events = store.get_audit_events(
        case.case_id
    )

    packet = case.packet

    mitre_techniques = packet.get(
        "mitre_techniques",
        [],
    )

    copilot_draft = None

    if isinstance(case.copilot_result, dict):
        draft = case.copilot_result.get(
            "draft"
        )

        if isinstance(draft, dict):
            copilot_draft = draft

    return templates.TemplateResponse(
        request=request,
        name="dashboard/case_detail.html",
        context={
            "case": case,
            "packet": packet,
            "mitre_techniques": mitre_techniques,
            "copilot_draft": copilot_draft,
            "audit_events": audit_events,
            "csrf_token": _csrf_token(
                request
            ),
            "case_statuses": sorted(
                ALLOWED_CASE_STATUSES
            ),
            "updated": (
                request.query_params.get(
                    "updated"
                )
                == "1"
            ),
        },
    )


@router.post(
    "/dashboard/cases/{case_id}/update"
)
def dashboard_case_update(
    request: Request,
    case_id: str,
    csrf_token: Annotated[
        str,
        Form(min_length=1),
    ],
    case_status: Annotated[
        str,
        Form(min_length=1),
    ],
    assigned_to: Annotated[
        str,
        Form(),
    ] = "",
    note: Annotated[
        str,
        Form(),
    ] = "",
) -> Response:
    """Update a case through the analyst dashboard."""

    if not _authenticated(request):
        return _login_redirect()

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    normalized_status = (
        case_status.strip().lower()
    )

    if (
        normalized_status
        not in ALLOWED_CASE_STATUSES
    ):
        return HTMLResponse(
            content=(
                "<h1>Invalid case status</h1>"
            ),
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
        )

    store = request.app.state.case_store

    try:
        store.update_case(
            case_id,
            status=normalized_status,
            assigned_to=assigned_to,
            note=note,
            actor=_current_account(request).email,
        )
    except KeyError:
        return HTMLResponse(
            content="<h1>Case not found</h1>",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    except ValueError as error:
        return HTMLResponse(
            content=(
                "<h1>Case update failed</h1>"
                f"<p>{error}</p>"
            ),
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
        )

    return RedirectResponse(
        url=(
            f"/dashboard/cases/{case_id}"
            "?updated=1"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
