from connector_lab.observability.metrics import (
    ConnectorFailureCategory,
    ConnectorMetricObservation,
    ConnectorMetricOutcome,
    InMemoryConnectorMetricsRecorder,
)


def test_metrics_recorder_returns_immutable_typed_snapshot() -> None:
    recorder = InMemoryConnectorMetricsRecorder()

    recorder.record(
        ConnectorMetricObservation(
            component="security_jobs_connector",
            operation="create_job",
            outcome=ConnectorMetricOutcome.SUCCEEDED,
            duration_seconds=0.25,
        ),
    )
    recorder.record(
        ConnectorMetricObservation(
            component="security_jobs_connector",
            operation="create_job",
            outcome=ConnectorMetricOutcome.FAILED,
            duration_seconds=0.5,
            failure_category=(ConnectorFailureCategory.AUTHENTICATION),
        ),
    )

    snapshot = recorder.snapshot()

    assert snapshot.total_requests == 2
    assert snapshot.successful_requests == 1
    assert snapshot.failed_requests == 1
    assert snapshot.authentication_failures == 1
    assert snapshot.connection_failures == 0
    assert snapshot.request_timeouts == 0
    assert snapshot.job_timeouts == 0
    assert snapshot.durations_seconds == (
        0.25,
        0.5,
    )

    recorder.record(
        ConnectorMetricObservation(
            component="security_jobs_connector",
            operation="get_job",
            outcome=ConnectorMetricOutcome.SUCCEEDED,
            duration_seconds=0.1,
        ),
    )

    assert snapshot.total_requests == 2
    assert snapshot.durations_seconds == (
        0.25,
        0.5,
    )
