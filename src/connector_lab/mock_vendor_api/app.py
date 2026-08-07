from datetime import UTC, datetime
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    status,
)

from connector_lab.mock_vendor_api.auth import (
    require_vendor_api_key,
)
from connector_lab.mock_vendor_api.models import (
    VendorAffectedEntity,
    VendorDetection,
    VendorDetectionPage,
    VendorEntityCategory,
    VendorObservable,
    VendorObservableKind,
)


def build_detections() -> tuple[VendorDetection, ...]:
    return (
        VendorDetection(
            detection_key="DET-1001",
            event_name="Suspicious sign-in pattern",
            details=("Multiple unusual authentication attempts detected."),
            risk_score=85,
            event_time=datetime(
                2026,
                8,
                3,
                10,
                0,
                tzinfo=UTC,
            ),
            tenant_ref="vendor-tenant-001",
            observables=(
                VendorObservable(
                    kind=VendorObservableKind.IP,
                    indicator="192.0.2.10",
                ),
            ),
            affected_entity=VendorAffectedEntity(
                category=VendorEntityCategory.WORKLOAD,
                key="asset-001",
                label="application-server-01",
            ),
        ),
        VendorDetection(
            detection_key="DET-1002",
            event_name="Unexpected domain communication",
            details=("A protected workload contacted an unusual domain."),
            risk_score=45,
            event_time=datetime(
                2026,
                8,
                3,
                10,
                5,
                tzinfo=UTC,
            ),
            tenant_ref="vendor-tenant-001",
            observables=(
                VendorObservable(
                    kind=VendorObservableKind.DOMAIN,
                    indicator="example.test",
                ),
            ),
            affected_entity=VendorAffectedEntity(
                category=VendorEntityCategory.CLOUD_OBJECT,
                key="cloud-object-002",
                label="analytics-workload",
            ),
        ),
    )


def resolve_cursor(
    cursor: str | None,
) -> int:
    if cursor is None:
        return 0

    if not cursor.startswith("cursor-"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor",
        )

    cursor_position = cursor.removeprefix("cursor-")

    try:
        item_number = int(cursor_position)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor",
        ) from error

    start_index = item_number - 1

    if start_index < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cursor",
        )

    return start_index


def create_app() -> FastAPI:
    api = FastAPI(
        title="Mock Vendor Detection API",
        description=("Educational cursor-paginated security detection API."),
    )
    detections = build_detections()

    @api.get(
        "/detections",
        response_model=VendorDetectionPage,
    )
    def list_detections(
        _: Annotated[
            None,
            Depends(require_vendor_api_key),
        ],
        limit: Annotated[
            int,
            Query(ge=1, le=100),
        ] = 50,
        cursor: str | None = None,
    ) -> VendorDetectionPage:
        start_index = resolve_cursor(cursor)

        if cursor is not None and start_index >= len(detections):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid cursor",
            )

        end_index = start_index + limit
        records = detections[start_index:end_index]

        next_cursor: str | None = None

        if end_index < len(detections):
            next_cursor = f"cursor-{end_index + 1}"

        return VendorDetectionPage(
            records=records,
            next_cursor=next_cursor,
        )

    return api


app = create_app()
