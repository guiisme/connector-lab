class AlertNormalizationError(Exception):
    """Raised when a vendor alert cannot be normalized."""

    def __init__(
        self,
        *,
        vendor: str,
        message: str,
    ) -> None:
        self.vendor = vendor
        super().__init__(message)
