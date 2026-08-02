import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanType,
)
from connector_lab.client.security_jobs_connector import (
    SecurityJobsConnector,
)
from connector_lab.observability.events import (
    OperationalEvent,
    OperationalEventOutcome,
)


class RecordingEventRecorder:
    def __init__(self) -> None:
        self.events: list[OperationalEvent] = []

    def record(
        self,
        event: OperationalEvent,
    ) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_create_job_records_correlated_operational_events() -> None:
    def handle_create_request(request: Request) -> Response:
        return Response(
            status_code=202,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": "pending",
            },
        )

    recorder = RecordingEventRecorder()
    transport = MockTransport(handle_create_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
        )

        await connector.create_job(
            ScanJobCreateRequest(
                external_reference="operation-001",
                target="server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
            correlation_id="correlation-001",
        )

    assert recorder.events == [
        OperationalEvent(
            correlation_id="correlation-001",
            component="security_jobs_connector",
            operation="create_job",
            outcome=OperationalEventOutcome.STARTED,
        ),
        OperationalEvent(
            correlation_id="correlation-001",
            component="security_jobs_connector",
            operation="create_job",
            outcome=OperationalEventOutcome.SUCCEEDED,
        ),
    ]


@pytest.mark.asyncio
async def test_create_job_generates_correlation_id_when_missing() -> None:
    generated_ids = 0

    def generate_correlation_id() -> str:
        nonlocal generated_ids
        generated_ids += 1
        return "generated-correlation-001"

    def handle_create_request(request: Request) -> Response:
        return Response(
            status_code=202,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": "pending",
            },
        )

    recorder = RecordingEventRecorder()
    transport = MockTransport(handle_create_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
            correlation_id_provider=generate_correlation_id,
        )

        await connector.create_job(
            ScanJobCreateRequest(
                external_reference="operation-001",
                target="server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
        )

    assert generated_ids == 1
    assert len(recorder.events) == 2
    assert {event.correlation_id for event in recorder.events} == {
        "generated-correlation-001"
    }
