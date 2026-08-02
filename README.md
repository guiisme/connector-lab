# Connector Lab

Educational lab for building API connectors and MSSP integrations.

## Purpose

This project explores how an MSSP portal can integrate cybersecurity tools,
normalize their data, and exchange information with systems such as ITSM
platforms.

The project is educational and evolves incrementally as new integration
concepts are studied.

## Requirements

- Python 3.12
- uv

## Setup

```bash
uv sync
```

## Running the mock API

Start the development server:

```bash
uv run uvicorn connector_lab.mock_api.app:app \
  --host 127.0.0.1 \
  --port 8000 \
  --reload
```

The interactive API documentation is available at:

- <http://127.0.0.1:8000/docs>

Check the service health:

```bash
curl http://127.0.0.1:8000/health
```

Retrieve a page of sample alerts:

```bash
curl \
  -H "X-API-Key: connector-lab-secret" \
  "http://127.0.0.1:8000/alerts?page=1&page_size=1"
```

Pagination parameters:

- `page`: page number starting at `1`; default is `1`
- `page_size`: items per page from `1` to `100`; default is `50`

The response includes `page`, `page_size`, `total`, and `has_next`
alongside the alert items.

The fixed API key is intended only for this educational mock API.

## Running the mock ITSM API

Start the ITSM development server:

```bash
uv run uvicorn connector_lab.mock_itsm_api.app:app \
  --host 127.0.0.1 \
  --port 8001
```

The interactive API documentation is available at:

- <http://127.0.0.1:8001/docs>

Create a simulated incident:

```bash
curl \
  -X POST \
  -H "X-API-Key: connector-lab-itsm-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "external_reference": "alert-001",
    "title": "Suspicious PowerShell execution",
    "description": "Created from cybersecurity alert alert-001",
    "priority": "high"
  }' \
  http://127.0.0.1:8001/incidents
```

Incident identifiers are sequential within each API process. Data is not
persisted after the process stops.

The fixed API key is intended only for this educational mock API.

## Running the mock OAuth 2.0 API

Start the OAuth development server:

```bash
uv run uvicorn connector_lab.mock_oauth_api.app:app \
  --host 127.0.0.1 \
  --port 8003
```

The interactive API documentation is available at:

- <http://127.0.0.1:8003/docs>

Request an access token using the Client Credentials flow:

```bash
curl \
  -X POST \
  -u "connector-lab-client:connector-lab-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=alerts:read" \
  http://127.0.0.1:8003/oauth/token
```

A successful request returns:

```json
{
  "access_token": "connector-lab-access-token",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "alerts:read"
}
```

The mock authorization server:

- authenticates clients with HTTP Basic credentials
- supports only the `client_credentials` grant
- accepts the `alerts:read` scope
- returns OAuth-compatible `invalid_client`, `unsupported_grant_type`, and
  `invalid_scope` errors

The access token and credentials are deterministic and intended only for this
educational lab. The `expires_in` value represents the token lifetime that
connectors will use in later exercises; the mock server does not persist or
actively revoke issued tokens.

## Using the ITSM connector

With the mock ITSM API running, create an incident through the connector:

```python
import asyncio

from httpx import AsyncClient

from connector_lab.client.itsm_connector import ITSMConnector
from connector_lab.client.itsm_models import (
    IncidentCreateRequest,
    IncidentPriority,
)


async def main() -> None:
    async with AsyncClient(timeout=5.0) as http_client:
        connector = ITSMConnector(
            base_url="http://127.0.0.1:8001",
            api_key="connector-lab-itsm-secret",
            http_client=http_client,
        )
        request = IncidentCreateRequest(
            external_reference="alert-001",
            title="Suspicious PowerShell execution",
            description="Created from cybersecurity alert alert-001",
            priority=IncidentPriority.HIGH,
        )

        incident = await connector.create_incident(request)

    print(incident.incident_id, incident.status)


asyncio.run(main())
```

The connector maps authentication, timeout, and connection failures to the
same connector-specific errors used by the alerts integration.

## Using the alerts connector

With the mock API running, the connector can retrieve and parse its alerts:

```python
import asyncio

from httpx import AsyncClient

from connector_lab.client.alerts_connector import AlertsConnector


async def main() -> None:
    async with AsyncClient(timeout=5.0) as http_client:
        connector = AlertsConnector(
            base_url="http://127.0.0.1:8000",
            api_key="connector-lab-secret",
            http_client=http_client,
            page_size=1,
        )

        alerts = await connector.list_alerts()

    for alert in alerts.items:
        print(alert.id, alert.severity, alert.title)


asyncio.run(main())
```
The connector follows `has_next` automatically and returns a single
consolidated collection. Consumers do not need to manage page numbers.

`page_size` is optional, defaults to `100`, and accepts values from `1` to
`100`.

## Alert-to-incident workflow

The workflow maps cybersecurity alerts into ITSM incident requests and keeps
the resulting correlations in memory.

With the alerts and ITSM connectors configured:

```python
from connector_lab.workflows.alert_to_incident import (
    AlertToIncidentWorkflow,
)

workflow = AlertToIncidentWorkflow(
    incident_creator=itsm_connector,
)

for alert in alerts.items:
    result = await workflow.process(alert)

    print(
        result.alert_id,
        result.incident_id,
        result.created,
    )
```

Alert severities are mapped directly to incident priorities:

- `low` to `low`
- `medium` to `medium`
- `high` to `high`
- `critical` to `critical`

The first processing of an alert creates an incident and returns
`created=True`. Reprocessing the same alert with the same workflow instance
returns the stored correlation with `created=False`.

Correlations exist only in memory. Restarting the process or creating another
workflow instance clears the idempotency state.

## Running the alerts webhook receiver

Start the webhook API:

```bash
uv run uvicorn connector_lab.webhook_api.app:app \
  --host 127.0.0.1 \
  --port 8002
```

The interactive API documentation is available at:

- <http://127.0.0.1:8002/docs>

Alert events are received through:

```text
POST /webhooks/alerts
```

Requests must include an `X-Webhook-Signature` header in this format:

```text
sha256=<hexadecimal HMAC digest>
```

Requests must also include an `X-Webhook-Timestamp` header containing the Unix
timestamp in seconds used when generating the signature.

The signed content is constructed as:

```text
<timestamp>.<raw request body>
```

The digest is calculated with HMAC-SHA256 over those exact bytes. Changing the
timestamp, whitespace, field order, or any payload value after signing makes
the signature invalid.

Delivery timestamps must be within 300 seconds of the receiver clock. Older
events and events more than 300 seconds in the future are rejected.

The receiver verifies the signature and timestamp before parsing and
validating the event:

- valid signature, timestamp, and payload: `202 Accepted`
- missing or invalid signature: `401 Unauthorized`
- missing, malformed, expired, or future timestamp: `401 Unauthorized`
- valid authentication with invalid payload: `422 Unprocessable Entity`
- repeated `event_id`: `202 Accepted` with status `duplicate`

Processed event IDs are stored only in memory and are isolated per application
instance. Restarting the process clears the event idempotency state.

The fixed webhook secret is intended only for this educational lab.

## Retrieving alerts with OAuth 2.0

The mock Cyber API also exposes an OAuth-protected alerts resource:

```text
GET /oauth/alerts
```

Request alerts with the Bearer token issued by the mock OAuth server:

```bash
curl \
  -H "Authorization: Bearer connector-lab-access-token" \
  "http://127.0.0.1:8000/oauth/alerts?page=1&page_size=1"
```

The OAuth resource returns the same typed and paginated alert collection as
the API Key endpoint. The original `/alerts` endpoint remains available for
comparing the two authentication mechanisms.

The resource server:

- requires an `Authorization: Bearer <token>` header
- rejects missing, malformed, and unknown tokens with `401 Unauthorized`
- rejects expired tokens with `401 Unauthorized`
- requires the `alerts:read` scope
- returns `403 Forbidden` when the token lacks the required scope

For this educational mock, the deterministic token is valid for 300 seconds
after the mock Cyber API starts. Restarting the API creates a new validation
window. The injectable clock is used by tests to validate expiration without
real waiting.

## Using the OAuth alerts connector

`OAuthTokenProvider` implements the Client Credentials flow and manages the
access-token lifecycle independently from the alerts connector.

With both mock APIs running:

```python
import asyncio

from httpx import AsyncClient

from connector_lab.client.oauth_alerts_connector import (
    OAuthAlertsConnector,
)
from connector_lab.client.oauth_token_provider import (
    OAuthTokenProvider,
)


async def main() -> None:
    async with AsyncClient(timeout=5.0) as http_client:
        token_provider = OAuthTokenProvider(
            token_url="http://127.0.0.1:8003/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
            expiration_margin_seconds=30,
        )
        connector = OAuthAlertsConnector(
            base_url="http://127.0.0.1:8000",
            token_provider=token_provider,
            http_client=http_client,
            page_size=1,
        )

        alerts = await connector.list_alerts()

    for alert in alerts.items:
        print(alert.id, alert.title)


asyncio.run(main())
```

The token provider:

- requests tokens using HTTP Basic client authentication
- parses successful and error responses into independent typed models
- caches a valid token between connector calls
- renews an expired token automatically
- renews before expiration using a configurable safety margin
- defaults `expiration_margin_seconds` to `30`
- maps invalid clients, invalid scopes, timeouts, and connection failures to
  connector-specific errors

The OAuth alerts connector sends the cached Bearer token to `/oauth/alerts`,
follows all available pages, and preserves the pagination safeguards of the
API Key connector.

## Connecting webhooks to the incident workflow

The webhook application can receive an alert processor through `create_app()`.
`AlertToIncidentWorkflow` satisfies this contract without coupling the API to
the concrete ITSM connector.

```python
from connector_lab.webhook_api.app import create_app
from connector_lab.workflows.alert_to_incident import (
    AlertToIncidentWorkflow,
)

workflow = AlertToIncidentWorkflow(
    incident_creator=itsm_connector,
)

integrated_app = create_app(
    alert_processor=workflow,
)
```

Authenticated webhook payloads are converted explicitly into the independent
`Alert` client model before processing.

An accepted and newly created incident returns:

```json
{
  "event_id": "event-001",
  "status": "accepted",
  "alert_id": "alert-001",
  "incident_id": "INC-0001",
  "created": true
}
```

The integration preserves two idempotency boundaries:

- repeated `event_id`: the webhook API returns `duplicate` without invoking the
  workflow again
- new `event_id` with an existing `alert_id`: the workflow returns the existing
  incident correlation with `created=false`

Authentication failures never invoke the alert processor. Event IDs are marked
as processed only after the processor completes successfully, allowing a
failed delivery to be retried.

## Running the mock security scan API

Start the asynchronous scan development server:

```bash
uv run uvicorn connector_lab.mock_scan_api.app:app \
  --host 127.0.0.1 \
  --port 8004
```

The interactive API documentation is available at:

- <http://127.0.0.1:8004/docs>

Create a scan job:

```bash
curl \
  -X POST \
  -H "X-API-Key: connector-lab-scan-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "external_reference": "operation-001",
    "target": "server.example.com",
    "scan_type": "vulnerability"
  }' \
  http://127.0.0.1:8004/scan-jobs
```

Retrieve its current state:

```bash
curl \
  -H "X-API-Key: connector-lab-scan-secret" \
  http://127.0.0.1:8004/scan-jobs/SCAN-0001
```

Cancel an active job:

```bash
curl \
  -X DELETE \
  -H "X-API-Key: connector-lab-scan-secret" \
  http://127.0.0.1:8004/scan-jobs/SCAN-0001
```

The mock lifecycle is deterministic:

- creation returns `pending`
- the first status request returns `running`
- the second status request returns `completed`
- additional status requests preserve the terminal result
- active jobs can transition to `cancelled`
- terminal jobs cannot be cancelled
- setting `simulate_failure=true` makes the second status request return
  `failed`

Job identifiers and state are stored only in memory and are isolated per
application instance. Restarting the process clears all jobs.

## Using the asynchronous security jobs connector

`SecurityJobsConnector` creates, monitors, and cancels asynchronous security
scan jobs through independent typed client models.

With the mock security scan API running:

```python
import asyncio

from httpx import AsyncClient

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanType,
)
from connector_lab.client.security_jobs_connector import (
    SecurityJobsConnector,
)


async def main() -> None:
    async with AsyncClient(timeout=5.0) as http_client:
        connector = SecurityJobsConnector(
            base_url="http://127.0.0.1:8004",
            api_key="connector-lab-scan-secret",
            http_client=http_client,
            poll_interval_seconds=0.5,
            poll_timeout_seconds=30.0,
        )

        job = await connector.create_and_wait(
            ScanJobCreateRequest(
                external_reference="operation-001",
                target="server.example.com",
                scan_type=ScanType.VULNERABILITY,
            ),
        )

    print(job.job_id, job.status)

    if job.result is not None:
        print(job.result.total_findings)


asyncio.run(main())
```

The connector:

- sends typed scan job creation requests
- retrieves typed job lifecycle states and results
- polls `pending` and `running` jobs until a terminal state
- supports configurable polling intervals
- enforces a global polling timeout
- allows active jobs to be cancelled explicitly
- maps failed and cancelled terminal states to connector-specific errors
- maps authentication, request timeout, and connection failures to
  connector-specific errors

The polling clock and sleep function are injectable, allowing lifecycle,
interval, and timeout behavior to be tested deterministically without real
waiting.

## Orchestrating idempotent security scans

`SecurityScanWorkflow` maps independent typed scan commands into asynchronous
connector operations while preventing duplicate jobs for the same operation.

```python
from connector_lab.client.scan_models import ScanType
from connector_lab.workflows.security_scan import (
    SecurityScanCommand,
    SecurityScanWorkflow,
)

workflow = SecurityScanWorkflow(
    security_jobs=security_jobs_connector,
)

result = await workflow.process(
    SecurityScanCommand(
        operation_id="operation-001",
        target="server.example.com",
        scan_type=ScanType.VULNERABILITY,
    ),
)
```

The workflow:

- maps a typed command into a scan job creation request
- correlates each `operation_id` with its resulting `job_id`
- creates and awaits one asynchronous job for a new operation
- returns `created=false` when an existing terminal result is reused
- represents completed, failed, and cancelled outcomes with typed results
- preserves the job correlation after a global polling timeout
- resumes the existing job after a timed-out operation is retried
- never stores a timeout as a terminal result

Correlations and terminal results are stored only in memory and are isolated
per workflow instance. Restarting the process clears the workflow idempotency
state.

## Connector resilience

The connector retries only responses with status `429 Too Many Requests`.

Default retry behavior:

- `max_retries=2`: two retries after the initial request
- `backoff_seconds=1.0`: exponential delays of 1 and 2 seconds
- authentication and other permanent HTTP errors are not retried
- timeout and connection failures are reported immediately

The connector exposes specific errors for authentication, timeouts, connection
failures, exhausted rate limits, and inconsistent pagination.

## Quality checks

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

## Initial structure

- `src/connector_lab/mock_api`: simulated cybersecurity product API
- `src/connector_lab/client`: connector responsible for consuming the API
- `tests`: automated tests
