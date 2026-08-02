import json
import logging

import pytest

from connector_lab.observability.events import (
    LoggingOperationalEventRecorder,
    OperationalEvent,
    OperationalEventOutcome,
)


class CapturingLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(
        self,
        record: logging.LogRecord,
    ) -> None:
        self.records.append(record)


@pytest.mark.parametrize(
    (
        "outcome",
        "error_type",
        "expected_level",
    ),
    [
        (
            OperationalEventOutcome.STARTED,
            None,
            logging.INFO,
        ),
        (
            OperationalEventOutcome.SUCCEEDED,
            None,
            logging.INFO,
        ),
        (
            OperationalEventOutcome.FAILED,
            "ConnectorTimeoutError",
            logging.ERROR,
        ),
    ],
)
def test_logging_recorder_emits_structured_json_event(
    outcome: OperationalEventOutcome,
    error_type: str | None,
    expected_level: int,
) -> None:
    logger = logging.getLogger(
        f"connector-lab-test-{outcome.value}",
    )
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = CapturingLogHandler()
    logger.addHandler(handler)

    recorder = LoggingOperationalEventRecorder(
        logger=logger,
    )
    recorder.record(
        OperationalEvent(
            correlation_id="correlation-001",
            component="security_jobs_connector",
            operation="create_job",
            outcome=outcome,
            error_type=error_type,
        ),
    )

    logger.removeHandler(handler)

    assert len(handler.records) == 1

    record = handler.records[0]
    assert record.levelno == expected_level
    assert json.loads(record.getMessage()) == {
        "component": "security_jobs_connector",
        "correlation_id": "correlation-001",
        "error_type": error_type,
        "operation": "create_job",
        "outcome": outcome.value,
    }
