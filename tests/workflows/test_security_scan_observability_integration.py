import json

import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
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
