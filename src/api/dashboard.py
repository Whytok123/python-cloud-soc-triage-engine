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
from src.identity.models import ALLOWED_ANALYST_ROLES
from src.identity.permissions import (
    Permission,
    has_permission,
)


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

    account = _current_account(request)

    if account is None:
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

    current_assignee = (
        case.assigned_to.strip().lower()
        if isinstance(case.assigned_to, str)
        and case.assigned_to.strip()
        else None
    )

    can_reassign_cases = has_permission(
        account.role,
        Permission.REASSIGN_CASES,
    )

    can_assign_self = (
        has_permission(
            account.role,
            Permission.ASSIGN_SELF,
        )
        and not can_reassign_cases
        and current_assignee is None
    )

    can_resolve_cases = has_permission(
        account.role,
        Permission.RESOLVE_CASES,
    )

    can_update_status = has_permission(
        account.role,
        Permission.UPDATE_CASE_STATUS,
    )

    can_add_notes = has_permission(
        account.role,
        Permission.ADD_NOTES,
    )

    available_case_statuses = sorted(
        status_name
        for status_name in ALLOWED_CASE_STATUSES
        if (
            can_resolve_cases
            or status_name
            not in TERMINAL_CASE_STATUSES
        )
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard/case_detail.html",
        context={
            "case": case,
            "current_account": account,
            "packet": packet,
            "mitre_techniques": mitre_techniques,
            "copilot_draft": copilot_draft,
            "audit_events": audit_events,
            "csrf_token": _csrf_token(
                request
            ),
            "case_statuses": available_case_statuses,
            "can_assign_self": can_assign_self,
            "can_reassign_cases": can_reassign_cases,
            "can_resolve_cases": can_resolve_cases,
            "can_update_status": can_update_status,
            "can_add_notes": can_add_notes,
            "updated": (
                request.query_params.get(
                    "updated"
                )
                == "1"
            ),
        },
    )


TERMINAL_CASE_STATUSES = {
    "resolved",
    "closed",
}


def _permission_denied(
    message: str,
) -> HTMLResponse:
    """Return a consistent RBAC denial response."""

    return HTMLResponse(
        content=(
            "<h1>Forbidden</h1>"
            f"<p>{message}</p>"
        ),
        status_code=status.HTTP_403_FORBIDDEN,
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
    """Update a case with role-based authorization."""

    account = _current_account(request)

    if account is None:
        return _login_redirect()

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    store = request.app.state.case_store
    case = store.get_case(case_id)

    if case is None:
        return HTMLResponse(
            content="<h1>Case not found</h1>",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    requested_status = (
        case_status.strip().lower()
    )

    if (
        requested_status
        not in ALLOWED_CASE_STATUSES
    ):
        return HTMLResponse(
            content="<h1>Invalid case status</h1>",
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
        )

    requested_assignee = (
        assigned_to.strip().lower()
        or None
    )

    current_assignee = (
        case.assigned_to.strip().lower()
        if isinstance(case.assigned_to, str)
        and case.assigned_to.strip()
        else None
    )

    normalized_note = note.strip()

    status_changed = (
        requested_status != case.status
    )

    assignment_changed = (
        requested_assignee
        != current_assignee
    )

    if normalized_note and not has_permission(
        account.role,
        Permission.ADD_NOTES,
    ):
        return _permission_denied(
            "Your role cannot add case notes."
        )

    if status_changed:
        if (
            requested_status
            in TERMINAL_CASE_STATUSES
        ):
            required_permission = (
                Permission.RESOLVE_CASES
            )
        else:
            required_permission = (
                Permission.UPDATE_CASE_STATUS
            )

        if not has_permission(
            account.role,
            required_permission,
        ):
            return _permission_denied(
                "Your role cannot perform this "
                "case-status transition."
            )

    if assignment_changed:
        assigning_to_self = (
            requested_assignee
            == account.email
            and current_assignee
            in {
                None,
                account.email,
            }
        )

        if assigning_to_self:
            allowed = has_permission(
                account.role,
                Permission.ASSIGN_SELF,
            )
        else:
            allowed = has_permission(
                account.role,
                Permission.REASSIGN_CASES,
            )

        if not allowed:
            return _permission_denied(
                "Your role cannot assign this "
                "case to another analyst."
            )

    if (
        not status_changed
        and not assignment_changed
        and not normalized_note
    ):
        return HTMLResponse(
            content=(
                "<h1>No changes submitted</h1>"
            ),
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
        )

    try:
        store.update_case(
            case_id,
            status=requested_status,
            assigned_to=(
                requested_assignee or ""
            ),
            note=normalized_note,
            actor=account.email,
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



def _active_admin_count(
    identity_store,
) -> int:
    """Count active administrator accounts."""

    return sum(
        1
        for analyst in identity_store.list_accounts()
        if (
            analyst.role == "admin"
            and analyst.is_active
        )
    )


def _admin_account(
    request: Request,
):
    """Return an authorized administrator."""

    account = _current_account(request)

    if account is None:
        return None

    if not has_permission(
        account.role,
        Permission.MANAGE_ANALYSTS,
    ):
        return False

    return account


@router.get(
    "/dashboard/admin/analysts",
    response_class=HTMLResponse,
)
def dashboard_admin_analysts(
    request: Request,
) -> Response:
    """Display analyst-account administration."""

    account = _admin_account(request)

    if account is None:
        return _login_redirect()

    if account is False:
        return _permission_denied(
            "Administrator access is required."
        )

    identity_store = (
        request.app.state.identity_store
    )

    analysts = identity_store.list_accounts()

    notice = request.query_params.get(
        "notice"
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard/admin/analysts.html",
        context={
            "current_account": account,
            "analysts": analysts,
            "analyst_roles": sorted(
                ALLOWED_ANALYST_ROLES
            ),
            "csrf_token": _csrf_token(request),
            "notice": notice,
        },
    )


@router.post(
    "/dashboard/admin/analysts/create"
)
def dashboard_admin_create_analyst(
    request: Request,
    csrf_token: Annotated[
        str,
        Form(min_length=1),
    ],
    email: Annotated[
        str,
        Form(min_length=3),
    ],
    display_name: Annotated[
        str,
        Form(min_length=1),
    ],
    role: Annotated[
        str,
        Form(min_length=1),
    ],
    password: Annotated[
        str,
        Form(min_length=12),
    ],
    password_confirmation: Annotated[
        str,
        Form(min_length=12),
    ],
) -> Response:
    """Create an analyst account as an admin."""

    account = _admin_account(request)

    if account is None:
        return _login_redirect()

    if account is False:
        return _permission_denied(
            "Administrator access is required."
        )

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    if password != password_confirmation:
        return HTMLResponse(
            content=(
                "<h1>Account creation failed</h1>"
                "<p>Passwords do not match.</p>"
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    normalized_role = role.strip().lower()

    if normalized_role not in (
        ALLOWED_ANALYST_ROLES
    ):
        return HTMLResponse(
            content=(
                "<h1>Account creation failed</h1>"
                "<p>Invalid analyst role.</p>"
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    identity_store = (
        request.app.state.identity_store
    )

    try:
        identity_store.create_account(
            email=email,
            display_name=display_name,
            password=password,
            role=normalized_role,
        )
    except ValueError as error:
        return HTMLResponse(
            content=(
                "<h1>Account creation failed</h1>"
                f"<p>{error}</p>"
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return RedirectResponse(
        url=(
            "/dashboard/admin/analysts"
            "?notice=created"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/dashboard/admin/analysts/{user_id}/role"
)
def dashboard_admin_update_role(
    request: Request,
    user_id: str,
    csrf_token: Annotated[
        str,
        Form(min_length=1),
    ],
    role: Annotated[
        str,
        Form(min_length=1),
    ],
) -> Response:
    """Change an analyst role as an admin."""

    account = _admin_account(request)

    if account is None:
        return _login_redirect()

    if account is False:
        return _permission_denied(
            "Administrator access is required."
        )

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    identity_store = (
        request.app.state.identity_store
    )

    target = identity_store.get_by_id(
        user_id
    )

    if target is None:
        return HTMLResponse(
            content="<h1>Account not found</h1>",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    normalized_role = role.strip().lower()

    if normalized_role not in (
        ALLOWED_ANALYST_ROLES
    ):
        return HTMLResponse(
            content="<h1>Invalid analyst role</h1>",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if (
        target.user_id == account.user_id
        and normalized_role != account.role
    ):
        return _permission_denied(
            "You cannot change your own "
            "administrator role."
        )

    removing_active_admin = (
        target.role == "admin"
        and target.is_active
        and normalized_role != "admin"
    )

    if (
        removing_active_admin
        and _active_admin_count(
            identity_store
        )
        <= 1
    ):
        return _permission_denied(
            "At least one active administrator "
            "must remain."
        )

    identity_store.update_role(
        target.user_id,
        role=normalized_role,
    )

    return RedirectResponse(
        url=(
            "/dashboard/admin/analysts"
            "?notice=role-updated"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/dashboard/admin/analysts/{user_id}/active"
)
def dashboard_admin_set_active(
    request: Request,
    user_id: str,
    csrf_token: Annotated[
        str,
        Form(min_length=1),
    ],
    is_active: Annotated[
        str,
        Form(min_length=1),
    ],
) -> Response:
    """Enable or disable an analyst account."""

    account = _admin_account(request)

    if account is None:
        return _login_redirect()

    if account is False:
        return _permission_denied(
            "Administrator access is required."
        )

    if not _valid_csrf_token(
        request,
        csrf_token,
    ):
        return _csrf_failure()

    identity_store = (
        request.app.state.identity_store
    )

    target = identity_store.get_by_id(
        user_id
    )

    if target is None:
        return HTMLResponse(
            content="<h1>Account not found</h1>",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    normalized_active = (
        is_active.strip().lower()
    )

    if normalized_active not in {
        "true",
        "false",
    }:
        return HTMLResponse(
            content="<h1>Invalid account state</h1>",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    desired_active = (
        normalized_active == "true"
    )

    if (
        target.user_id == account.user_id
        and not desired_active
    ):
        return _permission_denied(
            "You cannot disable your own account."
        )

    disabling_active_admin = (
        target.role == "admin"
        and target.is_active
        and not desired_active
    )

    if (
        disabling_active_admin
        and _active_admin_count(
            identity_store
        )
        <= 1
    ):
        return _permission_denied(
            "At least one active administrator "
            "must remain."
        )

    identity_store.set_active(
        target.user_id,
        is_active=desired_active,
    )

    notice = (
        "reactivated"
        if desired_active
        else "disabled"
    )

    return RedirectResponse(
        url=(
            "/dashboard/admin/analysts"
            f"?notice={notice}"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
