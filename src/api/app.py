"""FastAPI application for AI SOC Copilot Version 2."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    status,
)

from src.api.dependencies import (
    CaseStoreDependency,
    DatabasePathDependency,
    InputRootDependency,
)
from src.api.security import configure_api_key_auth
from src.api.schemas import (
    AuditEventResponse,
    CaseResponse,
    CaseStatus,
    CaseUpdateRequest,
    HealthResponse,
    PipelineResponse,
    SSHPipelineRequest,
)
from src.cases.store import SQLiteCaseStore
from src.orchestration.pipeline import (
    run_cross_source_ssh_pipeline,
)


API_VERSION = "2.0.0"


def _resolve_json_input(
    filename: str,
    input_root: Path,
) -> Path:
    """Resolve and validate a JSON input inside input_root.

    This prevents API clients from using path traversal to
    read arbitrary files outside the configured telemetry
    directory.
    """

    normalized_name = filename.strip()

    if not normalized_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Input filename is required",
        )

    root = input_root.resolve()

    supplied_path = Path(normalized_name)

    if supplied_path.is_absolute():
        candidate = supplied_path.resolve()
    else:
        candidate = (
            root / supplied_path
        ).resolve()

    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Input file must be inside the configured "
                "telemetry directory"
            ),
        ) from error

    if candidate.suffix.lower() != ".json":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only JSON telemetry files are supported",
        )

    if not candidate.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Input file not found: {normalized_name}",
        )

    if not candidate.is_file():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Telemetry input must be a regular file",
        )

    return candidate


def create_app(
    *,
    database_path: str | Path | None = None,
    input_root: str | Path | None = None,
    api_key: str | None = None,
) -> FastAPI:
    """Create and configure the SOC API application."""

    resolved_database = Path(
        database_path
        or os.getenv(
            "SOC_CASE_DATABASE",
            "data/cases/soc_cases.db",
        )
    )

    resolved_input_root = Path(
        input_root
        or os.getenv(
            "SOC_INPUT_ROOT",
            "data/test_events",
        )
    ).resolve()

    resolved_input_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    configured_api_key = (
        api_key
        if api_key is not None
        else os.getenv("SOC_API_KEY")
    )

    resolved_api_key = (
        configured_api_key.strip()
        if isinstance(configured_api_key, str)
        and configured_api_key.strip()
        else None
    )

    app = FastAPI(
        title="AI SOC Copilot API",
        description=(
            "Evidence-grounded multi-source security "
            "correlation, triage, Copilot, and case "
            "management API."
        ),
        version=API_VERSION,
    )

    app.state.database_path = resolved_database
    app.state.input_root = resolved_input_root
    app.state.case_store = SQLiteCaseStore(
        resolved_database
    )
    app.state.api_key = resolved_api_key

    configure_api_key_auth(app)

    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["system"],
    )
    def health() -> HealthResponse:
        """Return the API health status."""

        return HealthResponse(
            status="healthy",
            service="ai-soc-copilot",
            version=API_VERSION,
        )

    @app.get(
        "/cases",
        response_model=list[CaseResponse],
        tags=["cases"],
    )
    def list_cases(
        store: CaseStoreDependency,
        case_status: CaseStatus | None = Query(
            default=None,
            alias="status",
        ),
        limit: int = Query(
            default=100,
            ge=1,
            le=500,
        ),
    ) -> list[CaseResponse]:
        """List SOC cases, optionally filtered by status."""

        records = store.list_cases(
            status=case_status,
            limit=limit,
        )

        return [
            CaseResponse.model_validate(
                record.to_dict()
            )
            for record in records
        ]

    @app.get(
        "/cases/{case_id}",
        response_model=CaseResponse,
        tags=["cases"],
    )
    def get_case(
        case_id: str,
        store: CaseStoreDependency,
    ) -> CaseResponse:
        """Return one SOC case."""

        record = store.get_case(case_id)

        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case not found: {case_id}",
            )

        return CaseResponse.model_validate(
            record.to_dict()
        )

    @app.get(
        "/cases/{case_id}/audit",
        response_model=list[AuditEventResponse],
        tags=["cases"],
    )
    def get_case_audit(
        case_id: str,
        store: CaseStoreDependency,
    ) -> list[AuditEventResponse]:
        """Return the append-only audit history."""

        record = store.get_case(case_id)

        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case not found: {case_id}",
            )

        return [
            AuditEventResponse.model_validate(
                event.to_dict()
            )
            for event in store.get_audit_events(
                case_id
            )
        ]

    @app.patch(
        "/cases/{case_id}",
        response_model=CaseResponse,
        tags=["cases"],
    )
    def update_case(
        case_id: str,
        update: CaseUpdateRequest,
        store: CaseStoreDependency,
    ) -> CaseResponse:
        """Update status, assignment, or analyst notes."""

        try:
            record = store.update_case(
                case_id,
                status=update.status,
                assigned_to=update.assigned_to,
                note=update.note,
                actor=update.actor,
            )
        except KeyError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(error).strip("'"),
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error

        return CaseResponse.model_validate(
            record.to_dict()
        )

    @app.post(
        "/pipelines/ssh",
        response_model=PipelineResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["pipelines"],
    )
    def run_ssh_pipeline(
        request: SSHPipelineRequest,
        input_directory: InputRootDependency,
        case_database: DatabasePathDependency,
    ) -> PipelineResponse:
        """Run Snort and Wazuh SSH correlation."""

        snort_file = _resolve_json_input(
            request.snort_file,
            input_directory,
        )

        wazuh_file = _resolve_json_input(
            request.wazuh_file,
            input_directory,
        )

        try:
            summary = (
                run_cross_source_ssh_pipeline(
                    snort_file=snort_file,
                    wazuh_file=wazuh_file,
                    database_path=case_database,
                    provider_name=request.provider,
                    actor=request.actor,
                )
            )
        except FileNotFoundError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(error),
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(error),
            ) from error
        except RuntimeError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(error),
            ) from error

        return PipelineResponse.model_validate(
            summary.to_dict()
        )

    return app
