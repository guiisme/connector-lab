from datetime import UTC, datetime

import pytest

from connector_lab.client.itsm_models import (
    IncidentCreateRequest,
    IncidentCreateResponse,
    IncidentStatus,
)
from connector_lab.client.models import (
    Alert,
    AlertSeverity,
    AlertStatus,
)
from connector_lab.workflows.alert_to_incident import (
    AlertToIncidentWorkflow,
)


class FakeIncidentCreator:
    def __init__(self) -> None:
        self.requests: list[IncidentCreateRequest] = []

    async def create_incident(
        self,
        request: IncidentCreateRequest,
    ) -> IncidentCreateResponse:
        self.requests.append(request)

        return IncidentCreateResponse(
            incident_id="INC-0001",
            external_reference=request.external_reference,
            status=IncidentStatus.NEW,
        )


@pytest.mark.asyncio
async def test_new_alert_creates_mapped_incident() -> None:
    incident_creator = FakeIncidentCreator()
    workflow = AlertToIncidentWorkflow(
        incident_creator=incident_creator,
    )
    alert = Alert(
        id="alert-001",
        title="Suspicious PowerShell execution",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        detected_at=datetime(
            2026,
            7,
            31,
            18,
            0,
            tzinfo=UTC,
        ),
    )

    result = await workflow.process(alert)

    assert len(incident_creator.requests) == 1

    request = incident_creator.requests[0]
    assert request.external_reference == "alert-001"
    assert request.title == "Suspicious PowerShell execution"
    assert request.description == ("Created from cybersecurity alert alert-001")
    assert request.priority.value == "high"

    assert result.alert_id == "alert-001"
    assert result.incident_id == "INC-0001"
    assert result.created is True


@pytest.mark.asyncio
async def test_reprocessed_alert_returns_existing_correlation() -> None:
    incident_creator = FakeIncidentCreator()
    workflow = AlertToIncidentWorkflow(
        incident_creator=incident_creator,
    )
    alert = Alert(
        id="alert-001",
        title="Suspicious PowerShell execution",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        detected_at=datetime(
            2026,
            7,
            31,
            18,
            0,
            tzinfo=UTC,
        ),
    )

    first_result = await workflow.process(alert)
    second_result = await workflow.process(alert)

    assert len(incident_creator.requests) == 1

    assert first_result.alert_id == second_result.alert_id
    assert first_result.incident_id == second_result.incident_id
    assert first_result.created is True
    assert second_result.created is False
