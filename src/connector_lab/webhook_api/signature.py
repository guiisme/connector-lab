import hashlib
import hmac
from datetime import UTC, datetime

from fastapi import HTTPException, status

WEBHOOK_SECRET = "connector-lab-webhook-secret"
TIMESTAMP_TOLERANCE_SECONDS = 300


def verify_signature(
    *,
    payload: bytes,
    provided_signature: str | None,
    provided_timestamp: str | None,
    current_time: datetime,
) -> None:
    if provided_signature is None or provided_timestamp is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    signed_content = provided_timestamp.encode() + b"." + payload
    expected_digest = hmac.new(
        WEBHOOK_SECRET.encode(),
        signed_content,
        hashlib.sha256,
    ).hexdigest()
    expected_signature = f"sha256={expected_digest}"

    if not hmac.compare_digest(
        provided_signature,
        expected_signature,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        delivery_timestamp = int(provided_timestamp)
        delivery_time = datetime.fromtimestamp(
            delivery_timestamp,
            tz=UTC,
        )
    except (OSError, OverflowError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook timestamp",
        ) from error

    age_seconds = abs(
        (current_time - delivery_time).total_seconds(),
    )

    if age_seconds > TIMESTAMP_TOLERANCE_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook timestamp",
        )
