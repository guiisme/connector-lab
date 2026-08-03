import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

VENDOR_API_KEY = "connector-lab-vendor-secret"

vendor_api_key_header = APIKeyHeader(
    name="X-Vendor-API-Key",
    auto_error=False,
)


def require_vendor_api_key(
    api_key: Annotated[
        str | None,
        Depends(vendor_api_key_header),
    ],
) -> None:
    if api_key is None or not secrets.compare_digest(
        api_key,
        VENDOR_API_KEY,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid vendor API key",
        )
