from typing import Annotated

from fastapi import FastAPI, Header, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from connector_lab.webhook_api.models import (
    WebhookAcceptedResponse,
    WebhookAlertEvent,
)
from connector_lab.webhook_api.signature import verify_signature

app = FastAPI(
    title="Connector Lab Webhook API",
    description="Secure webhook receiver for integration studies.",
)


@app.post(
    "/webhooks/alerts",
    response_model=WebhookAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def receive_alert_webhook(
    request: Request,
    webhook_signature: Annotated[
        str | None,
        Header(alias="X-Webhook-Signature"),
    ] = None,
) -> WebhookAcceptedResponse:
    payload = await request.body()

    verify_signature(
        payload=payload,
        provided_signature=webhook_signature,
    )

    try:
        event = WebhookAlertEvent.model_validate_json(payload)
    except ValidationError as error:
        raise RequestValidationError(
            error.errors(),
            body=payload,
        ) from error

    return WebhookAcceptedResponse(
        event_id=event.event_id,
        status="accepted",
    )
