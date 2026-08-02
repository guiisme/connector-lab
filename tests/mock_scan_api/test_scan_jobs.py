import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_scan_api.app import app, create_app


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


@pytest.mark.asyncio
async def test_scan_job_progresses_to_stable_completed_result() -> None:
    test_app = create_app()
    transport = ASGITransport(app=test_app)
    headers = {
        "X-API-Key": "connector-lab-scan-secret",
    }

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        create_response = await client.post(
            "/scan-jobs",
            headers=headers,
            json={
                "external_reference": "operation-002",
                "target": "database.example.com",
                "scan_type": "vulnerability",
            },
        )
        job_id = create_response.json()["job_id"]

        running_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )
        completed_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )
        stable_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )

    assert running_response.status_code == 200
    assert running_response.json() == {
        "job_id": "SCAN-0001",
        "external_reference": "operation-002",
        "status": "running",
    }

    expected_completed = {
        "job_id": "SCAN-0001",
        "external_reference": "operation-002",
        "status": "completed",
        "result": {
            "total_findings": 3,
            "critical_findings": 1,
            "high_findings": 2,
        },
    }

    assert completed_response.status_code == 200
    assert completed_response.json() == expected_completed
    assert stable_response.status_code == 200
    assert stable_response.json() == expected_completed
