class ConnectorAuthenticationError(Exception):
    """Raised when the external API rejects connector credentials."""


class ConnectorPaginationError(Exception):
    """Raised when pagination metadata is inconsistent."""
