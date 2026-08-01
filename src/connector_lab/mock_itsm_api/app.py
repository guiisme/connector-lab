from itertools import count
from typing import Annotated

from fastapi import Depends, FastAPI, status

from connector_lab.mock_itsm_api.auth import require_api_key
from connector_lab.mock_itsm_api.models import (
    IncidentCreateRequest,
    IncidentCreateResponse,
    IncidentStatus,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Mock ITSM API",
        description="Simulated ITSM API for connector studies.",
    )
    incident_numbers = count(start=1)

    @app.post(
        "/incidents",
        response_model=IncidentCreateResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_incident(
        request: IncidentCreateRequest,
        _: Annotated[None, Depends(require_api_key)],
    ) -> IncidentCreateResponse:
        incident_number = next(incident_numbers)

        return IncidentCreateResponse(
            incident_id=f"INC-{incident_number:04}",
            external_reference=request.external_reference,
            status=IncidentStatus.NEW,
        )

    return app


app = create_app()
