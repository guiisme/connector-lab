import hashlib
import hmac

from fastapi import HTTPException, status

WEBHOOK_SECRET = "connector-lab-webhook-secret"


def verify_signature(
    *,
    payload: bytes,
    provided_signature: str | None,
) -> None:
    expected_digest = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    expected_signature = f"sha256={expected_digest}"

    if provided_signature is None or not hmac.compare_digest(
        provided_signature,
        expected_signature,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )
