class ConnectorAuthenticationError(Exception):
    """Raised when the external API rejects connector credentials."""


class ConnectorPaginationError(Exception):
    """Raised when pagination metadata is inconsistent."""


class ConnectorTimeoutError(Exception):
    """Raised when the external API does not respond within the timeout."""


class ConnectorConnectionError(Exception):
    """Raised when the connector cannot reach the external API."""


class ConnectorRateLimitError(Exception):
    """Raised when rate-limit retries are exhausted."""
