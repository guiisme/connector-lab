import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_scan_api.app import app


@pytest.mark.asyncio
async def test_create_scan_job_returns_pending_job() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/scan-jobs",
            headers={
                "X-API-Key": "connector-lab-scan-secret",
            },
            json={
                "external_reference": "operation-001",
                "target": "server.example.com",
                "scan_type": "vulnerability",
            },
        )

    assert response.status_code == 202
    assert response.json() == {
        "job_id": "SCAN-0001",
        "external_reference": "operation-001",
        "status": "pending",
    }
