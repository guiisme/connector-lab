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
