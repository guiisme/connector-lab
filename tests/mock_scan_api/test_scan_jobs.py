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


@pytest.mark.asyncio
async def test_active_scan_job_can_be_cancelled() -> None:
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
                "external_reference": "operation-cancel",
                "target": "application.example.com",
                "scan_type": "vulnerability",
            },
        )
        job_id = create_response.json()["job_id"]

        cancel_response = await client.delete(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )
        stable_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )

    expected_cancelled = {
        "job_id": "SCAN-0001",
        "external_reference": "operation-cancel",
        "status": "cancelled",
    }

    assert cancel_response.status_code == 200
    assert cancel_response.json() == expected_cancelled
    assert stable_response.status_code == 200
    assert stable_response.json() == expected_cancelled


@pytest.mark.asyncio
async def test_scan_job_progresses_to_stable_failed_state() -> None:
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
                "external_reference": "operation-failed",
                "target": "legacy.example.com",
                "scan_type": "vulnerability",
                "simulate_failure": True,
            },
        )
        job_id = create_response.json()["job_id"]

        running_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )
        failed_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )
        stable_response = await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )

    assert running_response.json()["status"] == "running"

    expected_failed = {
        "job_id": "SCAN-0001",
        "external_reference": "operation-failed",
        "status": "failed",
        "error": "Simulated scan failure",
    }

    assert failed_response.status_code == 200
    assert failed_response.json() == expected_failed
    assert stable_response.status_code == 200
    assert stable_response.json() == expected_failed


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {"X-API-Key": "invalid-key"},
    ],
)
@pytest.mark.asyncio
async def test_create_scan_job_rejects_invalid_authentication(
    headers: dict[str, str] | None,
) -> None:
    test_app = create_app()
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/scan-jobs",
            headers=headers,
            json={
                "external_reference": "operation-auth",
                "target": "server.example.com",
                "scan_type": "vulnerability",
            },
        )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid API key",
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "external_reference": "",
            "target": "server.example.com",
            "scan_type": "vulnerability",
        },
        {
            "external_reference": "operation-invalid",
            "target": "",
            "scan_type": "vulnerability",
        },
        {
            "external_reference": "operation-invalid",
            "target": "server.example.com",
            "scan_type": "unsupported",
        },
    ],
)
@pytest.mark.asyncio
async def test_create_scan_job_rejects_invalid_payload(
    payload: dict[str, object],
) -> None:
    test_app = create_app()
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/scan-jobs",
            headers={
                "X-API-Key": "connector-lab-scan-secret",
            },
            json=payload,
        )

    assert response.status_code == 422
    assert "detail" in response.json()


@pytest.mark.parametrize(
    "method",
    [
        "GET",
        "DELETE",
    ],
)
@pytest.mark.asyncio
async def test_unknown_scan_job_returns_not_found(
    method: str,
) -> None:
    test_app = create_app()
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.request(
            method,
            "/scan-jobs/SCAN-9999",
            headers={
                "X-API-Key": "connector-lab-scan-secret",
            },
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Scan job not found",
    }


@pytest.mark.asyncio
async def test_completed_scan_job_cannot_be_cancelled() -> None:
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
                "external_reference": "operation-completed",
                "target": "server.example.com",
                "scan_type": "vulnerability",
            },
        )
        job_id = create_response.json()["job_id"]

        await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )
        await client.get(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )

        cancel_response = await client.delete(
            f"/scan-jobs/{job_id}",
            headers=headers,
        )

    assert cancel_response.status_code == 409
    assert cancel_response.json() == {
        "detail": "Terminal scan job cannot be cancelled",
    }
