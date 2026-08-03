# Connector Lab â€” Project Contract and Progress

**Status:** Active  
**Contract baseline:** August 2026  
**Last reviewed:** August 3, 2026

## Document purpose

This document records the original intent, architectural boundaries, delivery
principles, completed progress, and planned evolution of Connector Lab.

The contract is formalized retrospectively from the original README, completed
milestones, implemented capabilities, and architectural decisions made during
the first seven development cycles.

It provides a stable reference against which future milestones can be
evaluated. It does not replace issue descriptions or implementation-specific
documentation.

## Original project intent

Connector Lab is an educational backend for studying API connectors and MSSP
integration patterns.

Its original purpose is to explore how an MSSP portal or cybersecurity
integration service can:

- connect to cybersecurity tools through external APIs
- receive security events through authenticated webhooks
- normalize data received from different security products
- exchange information with systems such as ITSM platforms
- orchestrate synchronous and asynchronous integration workflows
- preserve correlation and idempotency across operations
- represent authentication, transport, validation, and business failures
- expose enough operational telemetry to diagnose connector behavior

The project evolves incrementally. Each milestone isolates a specific
integration concept and introduces it through typed models, deterministic
tests, mock services, connectors, workflows, and documentation.

## Educational objectives

Connector Lab exists to study reusable integration engineering concepts rather
than reproduce a complete commercial MSSP platform.

The backend should demonstrate:

1. clear separation between external API schemas and internal models
2. typed communication at API, connector, and workflow boundaries
3. deterministic behavior for tests and educational inspection
4. dependency injection for clocks, waits, transports, recorders, and policies
5. idempotency and correlation across integration operations
6. explicit mapping of authentication, transport, timeout, and business errors
7. observability without leaking credentials or sensitive payloads
8. incremental development through test-driven changes
9. documentation that explains both usage and design intent

## Architectural principles

The project follows these principles:

- Python 3.12 as the implementation language
- FastAPI for simulated inbound and external APIs
- HTTPX for independent asynchronous connectors
- Pydantic for typed boundary and result models
- protocols for dependency inversion
- dependency injection for deterministic tests
- in-memory implementations during early educational cycles
- explicit connector-specific exception mapping
- immutable snapshots and models where appropriate
- vendor-neutral workflows whenever practical
- no dependency on a specific monitoring or integration vendor
- no credential, token, secret, header, target, or raw payload in telemetry

## Conceptual architecture

```text
External or simulated APIs
        â”‚
        â–¼
Vendor-specific typed connectors
        â”‚
        â–¼
Mapping and normalization boundaries
        â”‚
        â–¼
Idempotent integration workflows
        â”‚
        â”œâ”€â”€ ITSM operations
        â”œâ”€â”€ asynchronous security jobs
        â””â”€â”€ future multi-vendor processing
        â”‚
        â–¼
Structured events and operational metrics
```

## Original scope

The original backend scope includes:

- simulated cybersecurity APIs
- authenticated outbound connectors
- pagination and controlled retry behavior
- outbound ITSM integration
- inbound webhook processing
- API Key, HMAC, and OAuth 2.0 authentication patterns
- asynchronous security operations
- typed workflow results
- correlation and idempotency
- structured logging and operational metrics
- security data normalization

## Explicit non-goals

Connector Lab is not currently intended to be:

- a production MSSP portal
- a complete security operations platform
- a real credential vault
- a real message broker or distributed worker platform
- a replacement for commercial connector SDKs
- a persistent multi-tenant application
- a full SIEM, SOAR, EDR, ITSM, or vulnerability management product
- an implementation tied to a real cybersecurity vendor

Mock credentials and deterministic data exist only for local educational use.

## Development contract

Each capability should normally follow this sequence:

1. define one focused issue with explicit completion criteria
2. start from an updated `main` branch
3. create a dedicated feature branch
4. introduce a failing test that expresses the next behavior
5. implement the smallest coherent change
6. validate formatting, typing, and the complete test suite
7. create an intentional incremental commit
8. document externally visible behavior
9. review the complete branch diff
10. open and merge a squash pull request
11. confirm issue and milestone state
12. synchronize the local `main` branch

Required validation commands are:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
git diff --check
```

## Completed progress

### Milestone 01 â€” API Integration Fundamentals

**Status:** Completed

Delivered:

- Python project foundation
- authenticated mock cyber alerts API
- first typed HTTPX alerts connector
- basic API Key authentication
- typed request and response behavior

### Milestone 02 â€” Connector Resilience and Pagination

**Status:** Completed

Delivered:

- paginated alerts API
- automatic page traversal
- request timeout handling
- rate-limit handling
- controlled retries
- consolidated typed alert collections

### Milestone 03 â€” ITSM Incident Integration

**Status:** Completed

Delivered:

- authenticated mock ITSM incidents API
- typed ITSM connector
- alert-to-incident mapping
- correlation through external references
- idempotent alert-to-incident workflow

### Milestone 04 â€” Secure Webhook Event Processing

**Status:** Completed

Delivered:

- inbound alerts webhook API
- HMAC signature authentication
- replay protection
- typed webhook events
- idempotent event processing
- webhook-to-incident workflow integration

### Milestone 05 â€” OAuth 2.0 Connector Authentication

**Status:** Completed

Delivered:

- mock OAuth 2.0 token endpoint
- Client Credentials flow
- bearer-token-protected alerts
- scope validation
- typed token provider
- token caching and automatic renewal

### Milestone 06 â€” Asynchronous Security Job Processing

**Status:** Completed

Delivered:

- mock asynchronous security scan API
- pending, running, completed, failed, and cancelled states
- deterministic job polling
- explicit cancellation
- global polling timeout
- typed terminal results
- idempotent security scan workflow
- timeout recovery without duplicate job creation

### Milestone 07 â€” Connector Observability and Operational Telemetry

**Status:** Completed

Delivered:

- structured operational event models
- injectable event recorders
- JSON logging implementation
- correlation IDs across connector operations
- in-memory metrics collection
- immutable telemetry snapshots
- deterministic duration measurement
- authentication, connection, request-timeout, and job-timeout categories
- end-to-end workflow and connector correlation
- completed, failed, cancelled, timed-out, and reused scan telemetry
- protection against credentials and sensitive payloads in telemetry

## Current project position

At the completion of Milestone 07, Connector Lab has demonstrated one complete
backend integration vertical:

- simulated external APIs
- inbound and outbound integrations
- API Key, HMAC, and OAuth authentication
- synchronous and asynchronous connectors
- typed workflows
- correlation and idempotency
- controlled resilience behavior
- structured events and metrics
- deterministic automated tests

Current validation baseline:

- 7 completed milestones
- 21 completed milestone issues
- 145 automated tests
- Ruff checks passing
- Ruff formatting passing
- mypy passing
- complete pytest suite passing

## Progress against the original intent

| Original objective | Status | Notes |
|---|---|---|
| Connect to cybersecurity APIs | Completed | Alerts and security jobs connectors |
| Receive security events | Completed | Authenticated webhook processing |
| Exchange data with ITSM | Completed | Incident connector and workflow |
| Support common authentication patterns | Completed | API Key, HMAC, and OAuth 2.0 |
| Handle asynchronous operations | Completed | Polling, cancellation, and timeout |
| Preserve correlation and idempotency | Completed | ITSM, webhook, and scan workflows |
| Provide operational visibility | Completed | Structured events and metrics |
| Normalize multiple vendor schemas | Not completed | Planned for Milestone 08 |
| Detect API contract evolution | Not completed | Planned for Milestone 09 |
| Preserve state across restarts | Not completed | Planned for Milestone 10 |
| Discover and configure connectors dynamically | Not completed | Planned for Milestone 11 |
| Process integrations through durable queues | Not completed | Planned for Milestone 12 |

## Known limitations

The current backend intentionally retains these limitations:

- most workflow state is stored in memory
- restarting a process clears jobs, correlations, and cached results
- mock credentials are deterministic and stored in source code
- connectors are instantiated directly rather than through a registry
- only one primary alerts vendor schema has been modeled
- canonical multi-vendor security models do not yet exist
- API contract compatibility is not tracked automatically
- no durable queue, worker, or dead-letter processing exists
- retry and resilience policies are not yet generalized across connectors
- telemetry is held in memory unless a logging recorder is supplied

These limitations define future educational work rather than defects in the
current milestone scope.

## Approved forward roadmap

### Milestone 08 â€” Multi-Vendor Security Data Normalization

Planned outcomes:

- canonical vendor-neutral security alert model
- second simulated vendor API and connector
- vendor-specific normalization adapters
- canonical severity and source metadata
- correlation and deterministic deduplication
- multi-vendor normalization workflow

### Milestone 09 â€” Connector Contracts and Schema Evolution

Planned outcomes:

- explicit API contract artifacts
- contract validation tests
- compatibility rules
- versioned connector schemas
- schema drift detection
- safe handling of breaking and non-breaking changes

### Milestone 10 â€” Durable State and Persistent Idempotency

Planned outcomes:

- repository abstractions for workflow state
- persistent job and operation correlations
- durable terminal results
- restart-safe idempotency
- transactional state changes
- deterministic recovery tests

### Milestone 11 â€” Connector Registry and Configuration

Planned outcomes:

- typed connector descriptors
- connector registration and discovery
- independent vendor configuration
- credential references without secret exposure
- connector factories
- runtime connector selection

### Milestone 12 â€” Production-like Event Processing

Planned outcomes:

- queued integration commands
- independent workers
- explicit delivery semantics
- controlled retry and redelivery
- dead-letter handling
- graceful shutdown
- operational recovery and inspection

## Roadmap evaluation rule

A future milestone should be approved only when it:

- advances an unfinished objective from this contract
- introduces a distinct educational concept
- avoids duplicating an already completed milestone
- preserves architectural independence
- can be divided into small testable issues
- has deterministic completion criteria
- includes documentation and end-to-end validation

Changes to the project direction should update this document explicitly.

## Definition of project success

Connector Lab will have fulfilled its educational backend contract when it can
demonstrate:

- multiple vendor APIs with different schemas
- canonical security data independent from vendors
- contract-aware connector evolution
- durable and restart-safe integration workflows
- configurable connector discovery
- queue-based processing with observable recovery
- complete typed and deterministic tests across those boundaries

Completion of Milestone 12 should trigger a new review to decide whether the
project remains an educational backend or evolves into a broader integration
platform.