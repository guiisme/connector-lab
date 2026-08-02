class OAuthError(Exception):
    def __init__(
        self,
        *,
        error: str,
        status_code: int,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(error)
        self.error = error
        self.status_code = status_code
        self.headers = headers or {}
