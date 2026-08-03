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
from connector_lab.observability.metrics import (
    InMemoryConnectorMetricsRecorder,
)


@pytest.mark.asyncio
async def test_create_job_records_success_and_request_duration() -> None:
    clock_values = iter(
        [
            10.0,
            10.25,
        ],
    )

    def handle_create_request(request: Request) -> Response:
        return Response(
            status_code=202,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": "pending",
            },
        )

    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(handle_create_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            metrics_recorder=metrics,
            monotonic_provider=lambda: next(clock_values),
        )

        await connector.create_job(
            ScanJobCreateRequest(
                external_reference="operation-001",
                target="server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
        )

    snapshot = metrics.snapshot()

    assert snapshot.total_requests == 1
    assert snapshot.successful_requests == 1
    assert snapshot.failed_requests == 0
    assert snapshot.durations_seconds == (0.25,)
