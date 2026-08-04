import pytest
from pydantic import ValidationError

from connector_lab.client.vendor_alerts_models import (
    VendorDetectionListRequest,
)


def test_vendor_detection_list_request_preserves_pagination() -> None:
    request = VendorDetectionListRequest(
        limit=25,
        cursor="cursor-26",
    )

    assert request.limit == 25
    assert request.cursor == "cursor-26"
    assert request.model_dump(
        exclude_none=True,
    ) == {
        "limit": 25,
        "cursor": "cursor-26",
    }

    with pytest.raises(
        ValidationError,
        match="Instance is frozen",
    ):
        request.limit = 50


@pytest.mark.parametrize(
    "limit",
    [
        0,
        101,
    ],
)
def test_vendor_detection_list_request_rejects_invalid_limit(
    limit: int,
) -> None:
    with pytest.raises(ValidationError):
        VendorDetectionListRequest(
            limit=limit,
        )
