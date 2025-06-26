import httpx
from typing import Any
import time
from rich import print

from .config_manager import ConfigManager
from .exceptions import AuthenticationError

# This should be updated to your actual API's base URL
API_BASE_URL = "https://api.wafrunner.com/v1"
MAX_API_RETRIES = 3
API_RETRY_DELAY = 5  # seconds


class ApiClient:
    """Handles all HTTP requests to the wafrunner API."""

    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        config_manager = ConfigManager()
        token = config_manager.load_token()

        if not token:
            raise AuthenticationError(
                "API token not found. Please run 'wafrunner configure' first."
            )

        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "x-api-key": token,
                "Accept": "application/json",
            },
            timeout=30.0,
        )

    def _request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Internal request method with retry logic."""
        for attempt in range(MAX_API_RETRIES):
            try:
                response = self._client.request(method, endpoint, **kwargs)

                # Retry on 5xx server errors
                if 500 <= response.status_code < 600:
                    delay = API_RETRY_DELAY * (attempt + 1)
                    print(
                        f"[yellow]API server error ({response.status_code}). "
                        f"Retrying in {delay}s... ({attempt + 1}/{MAX_API_RETRIES})[/yellow]"
                    )
                    time.sleep(delay)
                    continue

                # For GET, a 404 is a valid "not found" response, not an error.
                if method.upper() == "GET" and response.status_code == 404:
                    return response

                # For POST, a 409 is a valid "conflict" response, not an error.
                if method.upper() == "POST" and response.status_code == 409:
                    return response

                response.raise_for_status()  # Raise for other 4xx client errors
                return response

            except httpx.HTTPStatusError as e:
                url = e.request.url
                if e.response.status_code == 401:
                    raise AuthenticationError(
                        f"Authentication failed (401 Unauthorized) for URL: {url}. "
                        "The API token is likely invalid or expired."
                    ) from e
                if e.response.status_code == 403:
                    raise AuthenticationError(
                        f"Authorization failed (403 Forbidden) for URL: {url}. "
                        "The API token is valid, but lacks permissions for this resource."
                    ) from e
                # Re-raise other status errors that are not handled by our retry logic.
                raise
            except httpx.TimeoutException as e:
                print(f"[bold red]Request Timeout:[/bold red] The request to {e.request.url!r} timed out.")
            except httpx.RequestError as e:
                print(f"[bold red]Network Error:[/bold red] An error occurred while requesting {e.request.url!r}.")

            if attempt < MAX_API_RETRIES - 1:
                delay = API_RETRY_DELAY * (attempt + 1)
                print(f"[yellow]Retrying in {delay}s... ({attempt + 1}/{MAX_API_RETRIES})[/yellow]")
                time.sleep(delay)

        raise httpx.RequestError(f"API request failed after {MAX_API_RETRIES} retries.")

    def get(self, endpoint: str, params: dict | None = None) -> Any:
        """Performs a GET request to a given API endpoint."""
        response = self._request("GET", endpoint, params=params)
        # Handle 404 Not Found gracefully
        if response.status_code == 404:
            return None
        return response.json()

    def post(self, endpoint: str, json: dict | None = None) -> Any:
        """Performs a POST request to a given API endpoint."""
        response = self._request("POST", endpoint, json=json)
        # Return the full response for POST to allow checking status_code (e.g., 201 vs 409)
        return response

    def put(self, endpoint: str, json: dict | None = None) -> Any:
        """Performs a PUT request to a given API endpoint."""
        response = self._request("PUT", endpoint, json=json)
        return response