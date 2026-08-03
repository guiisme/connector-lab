import json
from datetime import UTC, datetime, timedelta

import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.errors import (
    ConnectorJobTimeoutError,
)
from connector_lab.client.scan_models import (
    ScanJobStatus,
    ScanType,
)
from connector_lab.client.security_jobs_connector import (
    SecurityJobsConnector,
)
from connector_lab.observability.events import (
    OperationalEvent,
)
from connector_lab.observability.metrics import (
    InMemoryConnectorMetricsRecorder,
)
from connector_lab.workflows.security_scan import (
    SecurityScanCommand,
    SecurityScanWorkflow,
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
async def test_completed_scan_shares_events_and_metrics_correlation() -> None:
    request_methods: list[str] = []
    monotonic_values = iter(
        [
            10.0,
            10.1,
            10.2,
            10.3,
            10.4,
            10.5,
            10.6,
        ],
    )

    def handle_request(request: Request) -> Response:
        request_methods.append(request.method)

        if request.method == "POST":
            return Response(
                status_code=202,
                json={
                    "job_id": "SCAN-0001",
                    "external_reference": ("sensitive-operation-reference"),
                    "status": "pending",
                },
            )

        return Response(
            status_code=200,
            json={
                "job_id": "SCAN-0001",
                "external_reference": ("sensitive-operation-reference"),
                "status": "completed",
                "result": {
                    "total_findings": 3,
                    "critical_findings": 1,
                    "high_findings": 2,
                },
            },
        )

    recorder = RecordingEventRecorder()
    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(handle_request)

    def monotonic_provider() -> float:
        return next(monotonic_values)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
            metrics_recorder=metrics,
            monotonic_provider=monotonic_provider,
        )
        workflow = SecurityScanWorkflow(
            security_jobs=connector,
            event_recorder=recorder,
            metrics_recorder=metrics,
            correlation_id_provider=(lambda: "scan-correlation-e2e"),
            monotonic_provider=monotonic_provider,
        )

        result = await workflow.process(
            SecurityScanCommand(
                operation_id=("sensitive-operation-reference"),
                target="internal-server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
        )

    assert result.status is ScanJobStatus.COMPLETED
    assert request_methods == [
        "POST",
        "GET",
    ]

    assert {event.correlation_id for event in recorder.events} == {
        "scan-correlation-e2e",
    }
    assert {
        (
            event.component,
            event.operation,
            event.outcome.value,
        )
        for event in recorder.events
    } == {
        (
            "security_scan_workflow",
            "process_scan",
            "started",
        ),
        (
            "security_scan_workflow",
            "process_scan",
            "succeeded",
        ),
        (
            "security_jobs_connector",
            "create_job",
            "started",
        ),
        (
            "security_jobs_connector",
            "create_job",
            "succeeded",
        ),
        (
            "security_jobs_connector",
            "get_job",
            "started",
        ),
        (
            "security_jobs_connector",
            "get_job",
            "succeeded",
        ),
    }

    snapshot = metrics.snapshot()

    assert {observation.correlation_id for observation in snapshot.observations} == {
        "scan-correlation-e2e",
    }
    assert {
        (
            observation.component,
            observation.operation,
            observation.outcome.value,
        )
        for observation in snapshot.observations
    } == {
        (
            "security_jobs_connector",
            "create_job",
            "succeeded",
        ),
        (
            "security_jobs_connector",
            "get_job",
            "succeeded",
        ),
        (
            "security_scan_workflow",
            "process_scan",
            "succeeded",
        ),
    }

    serialized_telemetry = json.dumps(
        {
            "events": [event.model_dump(mode="json") for event in recorder.events],
            "metrics": [
                observation.model_dump(mode="json")
                for observation in snapshot.observations
            ],
        },
    )

    assert "connector-lab-scan-secret" not in serialized_telemetry
    assert "sensitive-operation-reference" not in serialized_telemetry
    assert "internal-server.example.com" not in serialized_telemetry
    assert "scan-correlation-e2e" in serialized_telemetry


@pytest.mark.parametrize(
    (
        "terminal_status",
        "expected_error_type",
        "expected_failure_category",
    ),
    [
        (
            "failed",
            "ConnectorJobFailedError",
            "job_failed",
        ),
        (
            "cancelled",
            "ConnectorJobCancelledError",
            "job_cancelled",
        ),
    ],
)
@pytest.mark.asyncio
async def test_unsuccessful_scan_has_specific_correlated_telemetry(
    terminal_status: str,
    expected_error_type: str,
    expected_failure_category: str,
) -> None:
    monotonic_values = iter(
        [
            20.0,
            20.1,
            20.2,
            20.3,
            20.4,
            20.5,
            20.6,
        ],
    )

    def monotonic_provider() -> float:
        return next(monotonic_values)

    def handle_request(request: Request) -> Response:
        if request.method == "POST":
            return Response(
                status_code=202,
                json={
                    "job_id": "SCAN-0002",
                    "external_reference": ("operation-unsuccessful-e2e"),
                    "status": "pending",
                },
            )

        payload: dict[str, object] = {
            "job_id": "SCAN-0002",
            "external_reference": ("operation-unsuccessful-e2e"),
            "status": terminal_status,
        }

        if terminal_status == "failed":
            payload["error"] = "Simulated scan failure"

        return Response(
            status_code=200,
            json=payload,
        )

    recorder = RecordingEventRecorder()
    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
            metrics_recorder=metrics,
            monotonic_provider=monotonic_provider,
        )
        workflow = SecurityScanWorkflow(
            security_jobs=connector,
            event_recorder=recorder,
            metrics_recorder=metrics,
            correlation_id_provider=(lambda: "scan-correlation-unsuccessful-e2e"),
            monotonic_provider=monotonic_provider,
        )

        result = await workflow.process(
            SecurityScanCommand(
                operation_id="operation-unsuccessful-e2e",
                target="server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
        )

    assert result.status.value == terminal_status

    workflow_failure_events = [
        event
        for event in recorder.events
        if (
            event.component == "security_scan_workflow"
            and event.outcome.value == "failed"
        )
    ]

    assert len(workflow_failure_events) == 1
    assert workflow_failure_events[0].correlation_id == (
        "scan-correlation-unsuccessful-e2e"
    )
    assert workflow_failure_events[0].error_type == (expected_error_type)

    workflow_observations = [
        observation
        for observation in metrics.snapshot().observations
        if observation.component == "security_scan_workflow"
    ]

    assert len(workflow_observations) == 1

    workflow_observation = workflow_observations[0]
    assert workflow_observation.correlation_id == ("scan-correlation-unsuccessful-e2e")
    assert workflow_observation.outcome.value == "failed"
    assert workflow_observation.failure_category is not None
    assert workflow_observation.failure_category.value == (expected_failure_category)


@pytest.mark.asyncio
async def test_timed_out_scan_has_correlated_workflow_and_connector_telemetry() -> None:
    fixed_now = datetime(
        2026,
        8,
        3,
        12,
        0,
        tzinfo=UTC,
    )
    clock_values = iter(
        [
            fixed_now,
            fixed_now + timedelta(seconds=6),
        ],
    )
    monotonic_values = iter(
        [
            30.0,
            30.1,
            30.2,
            30.3,
            30.4,
            30.5,
        ],
    )

    def now_provider() -> datetime:
        return next(clock_values)

    def monotonic_provider() -> float:
        return next(monotonic_values)

    def handle_request(request: Request) -> Response:
        assert request.method == "POST"

        return Response(
            status_code=202,
            json={
                "job_id": "SCAN-0003",
                "external_reference": "operation-timeout-e2e",
                "status": "pending",
            },
        )

    recorder = RecordingEventRecorder()
    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            poll_timeout_seconds=5.0,
            now_provider=now_provider,
            event_recorder=recorder,
            metrics_recorder=metrics,
            monotonic_provider=monotonic_provider,
        )
        workflow = SecurityScanWorkflow(
            security_jobs=connector,
            event_recorder=recorder,
            metrics_recorder=metrics,
            correlation_id_provider=(lambda: "scan-correlation-timeout-e2e"),
            monotonic_provider=monotonic_provider,
        )

        with pytest.raises(
            ConnectorJobTimeoutError,
            match="Security job polling timed out",
        ):
            await workflow.process(
                SecurityScanCommand(
                    operation_id="operation-timeout-e2e",
                    target="slow-server.example.com",
                    scan_type=ScanType.VULNERABILITY,
                ),
            )

    timeout_events = [
        event
        for event in recorder.events
        if event.error_type == "ConnectorJobTimeoutError"
    ]

    assert len(timeout_events) == 1
    assert timeout_events[0].component == ("security_scan_workflow")
    assert timeout_events[0].outcome.value == "failed"
    assert timeout_events[0].correlation_id == ("scan-correlation-timeout-e2e")

    timeout_observations = [
        observation
        for observation in metrics.snapshot().observations
        if (
            observation.failure_category is not None
            and observation.failure_category.value == "job_timeout"
        )
    ]

    assert {observation.component for observation in timeout_observations} == {
        "security_jobs_connector",
        "security_scan_workflow",
    }
    assert {observation.operation for observation in timeout_observations} == {
        "wait_for_job",
        "process_scan",
    }
    assert {observation.correlation_id for observation in timeout_observations} == {
        "scan-correlation-timeout-e2e",
    }

    snapshot = metrics.snapshot()

    assert snapshot.job_timeouts == 2
    assert snapshot.failed_requests == 2


@pytest.mark.asyncio
async def test_reprocessed_scan_reuses_result_and_correlation_without_http() -> None:
    request_methods: list[str] = []
    generated_correlation_ids: list[str] = []
    monotonic_values = iter(
        [
            40.0,
            40.1,
            40.2,
            40.3,
            40.4,
            40.5,
            40.6,
            40.7,
            40.8,
        ],
    )

    def monotonic_provider() -> float:
        return next(monotonic_values)

    def correlation_id_provider() -> str:
        correlation_id = "scan-correlation-reuse-e2e"
        generated_correlation_ids.append(correlation_id)
        return correlation_id

    def handle_request(request: Request) -> Response:
        request_methods.append(request.method)

        if request.method == "POST":
            return Response(
                status_code=202,
                json={
                    "job_id": "SCAN-0004",
                    "external_reference": "operation-reuse-e2e",
                    "status": "pending",
                },
            )

        return Response(
            status_code=200,
            json={
                "job_id": "SCAN-0004",
                "external_reference": "operation-reuse-e2e",
                "status": "completed",
                "result": {
                    "total_findings": 3,
                    "critical_findings": 1,
                    "high_findings": 2,
                },
            },
        )

    recorder = RecordingEventRecorder()
    metrics = InMemoryConnectorMetricsRecorder()
    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = SecurityJobsConnector(
            base_url="https://mock-scan.local",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            event_recorder=recorder,
            metrics_recorder=metrics,
            monotonic_provider=monotonic_provider,
        )
        workflow = SecurityScanWorkflow(
            security_jobs=connector,
            event_recorder=recorder,
            metrics_recorder=metrics,
            correlation_id_provider=correlation_id_provider,
            monotonic_provider=monotonic_provider,
        )
        command = SecurityScanCommand(
            operation_id="operation-reuse-e2e",
            target="server.example.com",
            scan_type=ScanType.VULNERABILITY,
        )

        first_result = await workflow.process(command)
        second_result = await workflow.process(command)

    assert first_result.created is True
    assert second_result.created is False
    assert second_result.job_id == first_result.job_id
    assert second_result.status is ScanJobStatus.COMPLETED

    assert generated_correlation_ids == [
        "scan-correlation-reuse-e2e",
    ]
    assert request_methods == [
        "POST",
        "GET",
    ]

    reuse_events = [
        event for event in recorder.events if event.operation == "reuse_scan_result"
    ]

    assert len(reuse_events) == 1
    assert reuse_events[0].component == ("security_scan_workflow")
    assert reuse_events[0].outcome.value == "succeeded"
    assert reuse_events[0].correlation_id == ("scan-correlation-reuse-e2e")

    observations = metrics.snapshot().observations

    connector_observations = [
        observation
        for observation in observations
        if observation.component == "security_jobs_connector"
    ]
    workflow_observations = [
        observation
        for observation in observations
        if observation.component == "security_scan_workflow"
    ]

    assert [observation.operation for observation in connector_observations] == [
        "create_job",
        "get_job",
    ]
    assert len(workflow_observations) == 2
    assert all(
        observation.operation == "process_scan" for observation in workflow_observations
    )
    assert all(
        observation.outcome.value == "succeeded"
        for observation in workflow_observations
    )
    assert {observation.correlation_id for observation in observations} == {
        "scan-correlation-reuse-e2e",
    }
