import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_vendor_api.app import app


@pytest.mark.asyncio
async def test_list_detections_returns_vendor_specific_first_page() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/detections",
            headers={
                "X-Vendor-API-Key": ("connector-lab-vendor-secret"),
            },
            params={
                "limit": 1,
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "records": [
            {
                "detection_key": "DET-1001",
                "event_name": "Suspicious sign-in pattern",
                "details": ("Multiple unusual authentication attempts detected."),
                "risk_score": 85,
                "event_time": "2026-08-03T10:00:00Z",
                "tenant_ref": "vendor-tenant-001",
                "observables": [
                    {
                        "kind": "ip",
                        "indicator": "192.0.2.10",
                    },
                ],
                "affected_entity": {
                    "category": "workload",
                    "key": "asset-001",
                    "label": "application-server-01",
                },
            },
        ],
        "next_cursor": "cursor-2",
    }


@pytest.mark.asyncio
async def test_list_detections_uses_cursor_for_next_page() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/detections",
            headers={
                "X-Vendor-API-Key": ("connector-lab-vendor-secret"),
            },
            params={
                "limit": 1,
                "cursor": "cursor-2",
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "records": [
            {
                "detection_key": "DET-1002",
                "event_name": "Unexpected domain communication",
                "details": ("A protected workload contacted an unusual domain."),
                "risk_score": 45,
                "event_time": "2026-08-03T10:05:00Z",
                "tenant_ref": "vendor-tenant-001",
                "observables": [
                    {
                        "kind": "domain",
                        "indicator": "example.test",
                    },
                ],
                "affected_entity": {
                    "category": "cloud_object",
                    "key": "cloud-object-002",
                    "label": "analytics-workload",
                },
            },
        ],
        "next_cursor": None,
    }


@pytest.mark.asyncio
async def test_list_detections_rejects_unknown_cursor() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/detections",
            headers={
                "X-Vendor-API-Key": ("connector-lab-vendor-secret"),
            },
            params={
                "cursor": "cursor-999",
            },
        )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Invalid cursor",
    }


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {
            "X-Vendor-API-Key": "invalid-vendor-key",
        },
    ],
)
@pytest.mark.asyncio
async def test_list_detections_rejects_invalid_authentication(
    headers: dict[str, str] | None,
) -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/detections",
            headers=headers,
        )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid vendor API key",
    }


@pytest.mark.parametrize(
    "limit",
    [
        0,
        101,
    ],
)
@pytest.mark.asyncio
async def test_list_detections_rejects_limit_outside_contract(
    limit: int,
) -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/detections",
            headers={
                "X-Vendor-API-Key": ("connector-lab-vendor-secret"),
            },
            params={
                "limit": limit,
            },
        )

    assert response.status_code == 422
