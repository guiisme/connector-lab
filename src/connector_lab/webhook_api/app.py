from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import FastAPI, Header, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from connector_lab.webhook_api.models import (
    WebhookAcceptedResponse,
    WebhookAlertEvent,
)
from connector_lab.webhook_api.signature import verify_signature

NowProvider = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def create_app(
    *,
    now_provider: NowProvider = utc_now,
) -> FastAPI:
    processed_event_ids: set[str] = set()

    api = FastAPI(
        title="Connector Lab Webhook API",
        description="Secure webhook receiver for integration studies.",
    )

    @api.post(
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
        webhook_timestamp: Annotated[
            str | None,
            Header(alias="X-Webhook-Timestamp"),
        ] = None,
    ) -> WebhookAcceptedResponse:
        payload = await request.body()

        verify_signature(
            payload=payload,
            provided_signature=webhook_signature,
            provided_timestamp=webhook_timestamp,
            current_time=now_provider(),
        )

        try:
            event = WebhookAlertEvent.model_validate_json(payload)
        except ValidationError as error:
            raise RequestValidationError(
                error.errors(),
                body=payload,
            ) from error

        if event.event_id in processed_event_ids:
            return WebhookAcceptedResponse(
                event_id=event.event_id,
                status="duplicate",
            )

        processed_event_ids.add(event.event_id)

        return WebhookAcceptedResponse(
            event_id=event.event_id,
            status="accepted",
        )

    return api


app = create_app()
