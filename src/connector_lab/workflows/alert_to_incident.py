from typing import Protocol

from pydantic import BaseModel

from connector_lab.client.itsm_models import (
    IncidentCreateRequest,
    IncidentCreateResponse,
    IncidentPriority,
)
from connector_lab.client.models import Alert


class IncidentCreator(Protocol):
    async def create_incident(
        self,
        request: IncidentCreateRequest,
    ) -> IncidentCreateResponse: ...


class AlertIncidentResult(BaseModel):
    alert_id: str
    incident_id: str
    created: bool


class AlertToIncidentWorkflow:
    def __init__(
        self,
        *,
        incident_creator: IncidentCreator,
    ) -> None:
        self._incident_creator = incident_creator
        self._correlations: dict[str, str] = {}

    async def process(
        self,
        alert: Alert,
    ) -> AlertIncidentResult:
        existing_incident_id = self._correlations.get(alert.id)

        if existing_incident_id is not None:
            return AlertIncidentResult(
                alert_id=alert.id,
                incident_id=existing_incident_id,
                created=False,
            )

        request = IncidentCreateRequest(
            external_reference=alert.id,
            title=alert.title,
            description=(f"Created from cybersecurity alert {alert.id}"),
            priority=IncidentPriority(alert.severity.value),
        )

        incident = await self._incident_creator.create_incident(
            request,
        )

        self._correlations[alert.id] = incident.incident_id

        return AlertIncidentResult(
            alert_id=alert.id,
            incident_id=incident.incident_id,
            created=True,
        )
