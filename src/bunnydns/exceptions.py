"""Exception classes for the Bunny DNS API client."""


class BunnyDNSError(Exception):
    """Base exception for all Bunny DNS API errors."""


class BunnyDNSAuthenticationError(BunnyDNSError):
    """Raised when the API returns a 401 Unauthorized response."""


class BunnyDNSNotFoundError(BunnyDNSError):
    """Raised when the API returns a 404 Not Found response."""


class BunnyDNSAPIError(BunnyDNSError):
    """Raised for any other non-success HTTP status code."""

    def __init__(self, status_code: int, message: str = ""):
        self.status_code = status_code
        super().__init__(
            f"HTTP {status_code}: {message}" if message else f"HTTP {status_code}"
        )
