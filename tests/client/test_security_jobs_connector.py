import json

import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobStatus,
    ScanType,
)
from connector_lab.client.security_jobs_connector import (
    SecurityJobsConnector,
)


@pytest.mark.asyncio
async def test_create_job_sends_typed_request() -> None:
    def handle_create_request(request: Request) -> Response:
        assert request.method == "POST"
        assert str(request.url) == ("https://mock-scan.local/scan-jobs")
        assert request.headers["X-API-Key"] == ("connector-lab-scan-secret")
        assert json.loads(request.content) == {
            "external_reference": "operation-001",
            "target": "server.example.com",
            "scan_type": "vulnerability",
            "simulate_failure": False,
        }

        return Response(
            status_code=202,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": "pending",
            },
        )

    transport = MockTransport(handle_create_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local/",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
        )
        request = ScanJobCreateRequest(
            external_reference="operation-001",
            target="server.example.com",
            scan_type=ScanType.VULNERABILITY,
        )

        job = await connector.create_job(request)

    assert job.job_id == "SCAN-0001"
    assert job.external_reference == "operation-001"
    assert job.status is ScanJobStatus.PENDING
