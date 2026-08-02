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
    ConnectorTimeoutError,
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


@pytest.mark.parametrize(
    (
        "failure_kind",
        "expected_error",
        "expected_error_type",
    ),
    [
        (
            "authentication",
            ConnectorAuthenticationError,
            "ConnectorAuthenticationError",
        ),
        (
            "timeout",
            ConnectorTimeoutError,
            "ConnectorTimeoutError",
        ),
        (
            "connection",
            ConnectorConnectionError,
            "ConnectorConnectionError",
        ),
    ],
)
@pytest.mark.asyncio
async def test_create_job_records_correlated_failure_event(
    failure_kind: str,
    expected_error: type[Exception],
    expected_error_type: str,
) -> None:
    def handle_failure(request: Request) -> Response:
        if failure_kind == "authentication":
            return Response(
                status_code=401,
                json={
                    "detail": "Invalid API key",
                },
            )

        if failure_kind == "timeout":
            raise ReadTimeout(
                "Security jobs API timed out",
                request=request,
            )

        raise ConnectError(
            "Security jobs API is unavailable",
            request=request,
        )

    recorder = RecordingEventRecorder()
    transport = MockTransport(handle_failure)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
        )
        request = ScanJobCreateRequest(
            external_reference="operation-001",
            target="server.example.com",
            scan_type=ScanType.VULNERABILITY,
        )

        with pytest.raises(expected_error):
            await connector.create_job(
                request,
                correlation_id="correlation-failed",
            )

    assert len(recorder.events) == 2
    assert recorder.events[0].outcome is (OperationalEventOutcome.STARTED)
    assert recorder.events[1] == OperationalEvent(
        correlation_id="correlation-failed",
        component="security_jobs_connector",
        operation="create_job",
        outcome=OperationalEventOutcome.FAILED,
        error_type=expected_error_type,
    )


@pytest.mark.parametrize(
    (
        "operation",
        "http_method",
        "response_status",
    ),
    [
        (
            "get_job",
            "GET",
            "completed",
        ),
        (
            "cancel_job",
            "DELETE",
            "cancelled",
        ),
    ],
)
@pytest.mark.asyncio
async def test_job_operation_records_correlated_success_events(
    operation: str,
    http_method: str,
    response_status: str,
) -> None:
    def handle_request(request: Request) -> Response:
        assert request.method == http_method

        return Response(
            status_code=200,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": response_status,
            },
        )

    recorder = RecordingEventRecorder()
    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
        )

        if operation == "get_job":
            await connector.get_job(
                "SCAN-0001",
                correlation_id="correlation-job",
            )
        else:
            await connector.cancel_job(
                "SCAN-0001",
                correlation_id="correlation-job",
            )

    assert recorder.events == [
        OperationalEvent(
            correlation_id="correlation-job",
            component="security_jobs_connector",
            operation=operation,
            outcome=OperationalEventOutcome.STARTED,
        ),
        OperationalEvent(
            correlation_id="correlation-job",
            component="security_jobs_connector",
            operation=operation,
            outcome=OperationalEventOutcome.SUCCEEDED,
        ),
    ]


@pytest.mark.asyncio
async def test_create_and_wait_reuses_one_generated_correlation_id() -> None:
    generated_ids = 0
    status_requests = 0

    def generate_correlation_id() -> str:
        nonlocal generated_ids
        generated_ids += 1
        return f"generated-correlation-{generated_ids}"

    async def fake_sleep(delay: float) -> None:
        pass

    def handle_request(request: Request) -> Response:
        nonlocal status_requests

        if request.method == "POST":
            return Response(
                status_code=202,
                json={
                    "job_id": "SCAN-0001",
                    "external_reference": "operation-001",
                    "status": "pending",
                },
            )

        status_requests += 1
        status_value = "running" if status_requests == 1 else "completed"

        return Response(
            status_code=200,
            json={
                "job_id": "SCAN-0001",
                "external_reference": "operation-001",
                "status": status_value,
            },
        )

    recorder = RecordingEventRecorder()
    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            poll_interval_seconds=0,
            sleep_func=fake_sleep,
            event_recorder=recorder,
            correlation_id_provider=generate_correlation_id,
        )

        await connector.create_and_wait(
            ScanJobCreateRequest(
                external_reference="operation-001",
                target="server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
        )

    assert generated_ids == 1
    assert [event.operation for event in recorder.events] == [
        "create_job",
        "create_job",
        "get_job",
        "get_job",
        "get_job",
        "get_job",
    ]
    assert {event.correlation_id for event in recorder.events} == {
        "generated-correlation-1"
    }
