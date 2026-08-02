import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

SCAN_API_KEY = "connector-lab-scan-secret"

api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def require_api_key(
    api_key: Annotated[
        str | None,
        Depends(api_key_header),
    ],
) -> None:
    if api_key is None or not secrets.compare_digest(
        api_key,
        SCAN_API_KEY,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
