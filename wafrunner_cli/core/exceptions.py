class WafrunnerError(Exception):
    """Base exception for the wafrunner CLI."""

    pass


class AuthenticationError(WafrunnerError):
    """Raised when the API token is not configured."""

    pass
