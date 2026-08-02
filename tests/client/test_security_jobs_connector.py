import json
from datetime import UTC, datetime, timedelta

import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.errors import ConnectorJobTimeoutError
from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobStatus,
    ScanJobStatusResponse,
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


@pytest.mark.asyncio
async def test_get_job_returns_typed_completed_result() -> None:
    def handle_status_request(request: Request) -> Response:
        assert request.method == "GET"
        assert str(request.url) == ("https://mock-scan.local/scan-jobs/SCAN-0001")
        assert request.headers["X-API-Key"] == ("connector-lab-scan-secret")

        return Response(
            status_code=200,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": "completed",
                "result": {
                    "total_findings": 3,
                    "critical_findings": 1,
                    "high_findings": 2,
                },
            },
        )

    transport = MockTransport(handle_status_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
        )

        job = await connector.get_job("SCAN-0001")

    assert isinstance(job, ScanJobStatusResponse)
    assert job.status is ScanJobStatus.COMPLETED
    assert job.result is not None
    assert job.result.total_findings == 3
    assert job.result.critical_findings == 1
    assert job.result.high_findings == 2


@pytest.mark.asyncio
async def test_wait_for_job_polls_until_completion() -> None:
    requested_statuses: list[str] = []
    sleep_delays: list[float] = []
    statuses = [
        "pending",
        "running",
        "completed",
    ]

    async def fake_sleep(delay: float) -> None:
        sleep_delays.append(delay)

    def handle_status_request(request: Request) -> Response:
        status_value = statuses[len(requested_statuses)]
        requested_statuses.append(status_value)

        payload: dict[str, object] = {
            "job_id": "SCAN-0001",
            "external_reference": "operation-001",
            "status": status_value,
        }

        if status_value == "completed":
            payload["result"] = {
                "total_findings": 3,
                "critical_findings": 1,
                "high_findings": 2,
            }

        return Response(
            status_code=200,
            json=payload,
        )

    transport = MockTransport(handle_status_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            poll_interval_seconds=2.0,
            sleep_func=fake_sleep,
        )

        job = await connector.wait_for_job("SCAN-0001")

    assert requested_statuses == [
        "pending",
        "running",
        "completed",
    ]
    assert sleep_delays == [
        2.0,
        2.0,
    ]
    assert job.status is ScanJobStatus.COMPLETED
    assert job.result is not None
    assert job.result.total_findings == 3


@pytest.mark.asyncio
async def test_wait_for_job_stops_after_global_timeout() -> None:
    fixed_now = datetime(
        2026,
        8,
        2,
        12,
        0,
        tzinfo=UTC,
    )
    clock_values = iter(
        [
            fixed_now,
            fixed_now,
            fixed_now + timedelta(seconds=6),
        ],
    )
    status_requests = 0
    sleep_delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleep_delays.append(delay)

    def handle_pending_status(request: Request) -> Response:
        nonlocal status_requests
        status_requests += 1

        return Response(
            status_code=200,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-timeout",
                "status": "pending",
            },
        )

    transport = MockTransport(handle_pending_status)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            poll_interval_seconds=2.0,
            poll_timeout_seconds=5.0,
            sleep_func=fake_sleep,
            now_provider=lambda: next(clock_values),
        )

        with pytest.raises(
            ConnectorJobTimeoutError,
            match="Security job polling timed out",
        ):
            await connector.wait_for_job("SCAN-0001")

    assert status_requests == 1
    assert sleep_delays == [2.0]
