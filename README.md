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