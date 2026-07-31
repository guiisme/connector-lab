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

Retrieve sample alerts:

```bash
curl \
  -H "X-API-Key: connector-lab-secret" \
  http://127.0.0.1:8000/alerts
```

The fixed API key is intended only for this educational mock API.

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
