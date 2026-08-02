from typing import Literal

from pydantic import BaseModel, Field


class OAuthToken(BaseModel):
    access_token: str = Field(min_length=1)
    token_type: Literal["Bearer"]
    expires_in: int = Field(gt=0)
    scope: str
