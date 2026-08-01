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

    async def process(
        self,
        alert: Alert,
    ) -> AlertIncidentResult:
        request = IncidentCreateRequest(
            external_reference=alert.id,
            title=alert.title,
            description=(f"Created from cybersecurity alert {alert.id}"),
            priority=IncidentPriority(alert.severity.value),
        )

        incident = await self._incident_creator.create_incident(
            request,
        )

        return AlertIncidentResult(
            alert_id=alert.id,
            incident_id=incident.incident_id,
            created=True,
        )
