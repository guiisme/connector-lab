from datetime import UTC, datetime, timedelta

import pytest
from httpx import (
    AsyncClient,
    ConnectError,
    MockTransport,
    ReadTimeout,
    Request,
    Response,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorJobTimeoutError,
    ConnectorTimeoutError,
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


@pytest.mark.parametrize(
    (
        "failure_kind",
        "expected_error",
        "expected_failure_counts",
    ),
    [
        (
            "authentication",
            ConnectorAuthenticationError,
            (1, 0, 0),
        ),
        (
            "connection",
            ConnectorConnectionError,
            (0, 1, 0),
        ),
        (
            "request_timeout",
            ConnectorTimeoutError,
            (0, 0, 1),
        ),
    ],
)
@pytest.mark.asyncio
async def test_create_job_records_categorized_request_failure(
    failure_kind: str,
    expected_error: type[Exception],
    expected_failure_counts: tuple[int, int, int],
) -> None:
    clock_values = iter(
        [
            20.0,
            20.5,
        ],
    )

    def handle_failure(request: Request) -> Response:
        if failure_kind == "authentication":
            return Response(
                status_code=401,
                json={
                    "detail": "Invalid API key",
                },
            )

        if failure_kind == "connection":
            raise ConnectError(
                "Security jobs API is unavailable",
                request=request,
            )

        raise ReadTimeout(
            "Security jobs API timed out",
            request=request,
        )

    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(handle_failure)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            metrics_recorder=metrics,
            monotonic_provider=lambda: next(clock_values),
        )
        request = ScanJobCreateRequest(
            external_reference="operation-failed",
            target="server.example.com",
            scan_type=ScanType.VULNERABILITY,
        )

        with pytest.raises(expected_error):
            await connector.create_job(request)

    snapshot = metrics.snapshot()

    assert snapshot.total_requests == 1
    assert snapshot.successful_requests == 0
    assert snapshot.failed_requests == 1
    assert (
        snapshot.authentication_failures,
        snapshot.connection_failures,
        snapshot.request_timeouts,
    ) == expected_failure_counts
    assert snapshot.job_timeouts == 0
    assert snapshot.durations_seconds == (0.5,)


@pytest.mark.asyncio
async def test_wait_for_job_records_global_job_timeout() -> None:
    started_at = datetime(
        2026,
        8,
        3,
        12,
        0,
        tzinfo=UTC,
    )
    clock_values = iter(
        [
            started_at,
            started_at + timedelta(seconds=6),
        ],
    )
    monotonic_values = iter(
        [
            30.0,
            35.0,
        ],
    )

    def unexpected_request(request: Request) -> Response:
        raise AssertionError(
            "Polling timeout should occur before HTTP request",
        )

    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(unexpected_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            poll_timeout_seconds=5.0,
            now_provider=lambda: next(clock_values),
            metrics_recorder=metrics,
            monotonic_provider=lambda: next(
                monotonic_values,
            ),
        )

        with pytest.raises(
            ConnectorJobTimeoutError,
            match="Security job polling timed out",
        ):
            await connector.wait_for_job("SCAN-0001")

    snapshot = metrics.snapshot()

    assert snapshot.total_requests == 1
    assert snapshot.successful_requests == 0
    assert snapshot.failed_requests == 1
    assert snapshot.job_timeouts == 1
    assert snapshot.authentication_failures == 0
    assert snapshot.connection_failures == 0
    assert snapshot.request_timeouts == 0
    assert snapshot.durations_seconds == (5.0,)
