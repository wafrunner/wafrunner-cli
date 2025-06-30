import httpx
from typing import Any
import time
import random # Import the random module
from rich import print

from .config_manager import ConfigManager
from .exceptions import AuthenticationError

# This should be updated to your actual API's base URL
API_BASE_URL = "https://api.wafrunner.com/v1"
MAX_API_RETRIES = 5 # Increased retries for more resilience
API_RETRY_BASE_DELAY = 2.5 # Base delay in seconds for exponential backoff

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
        """Internal request method with exponential backoff and jitter."""
        for attempt in range(MAX_API_RETRIES):
            try:
                response = self._client.request(method, endpoint, **kwargs)

                # Retry on 5xx server errors, which indicate transient issues
                if 500 <= response.status_code < 600:
                    # --- EXPONENTIAL BACKOFF LOGIC ---
                    # Calculate delay: base_delay * (2^attempt) + random_jitter
                    backoff_delay = API_RETRY_BASE_DELAY * (2 ** attempt)
                    jitter = random.uniform(0, backoff_delay * 0.1) # add up to 10% jitter
                    delay = backoff_delay + jitter

                    # Check if this is the last attempt
                    if attempt == MAX_API_RETRIES - 1:
                        # Log final failure and break the loop
                        print(f"[bold red]API server error ({response.status_code}). Final attempt failed. No more retries.[/bold red]")
                        break
                    
                    print(
                        f"[yellow]API server error ({response.status_code}). Server may be warming up. "
                        f"Retrying in {delay:.2f}s... (Attempt {attempt + 1}/{MAX_API_RETRIES})[/yellow]"
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
                # ... (rest of your exception handling is good)
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
                raise
            except httpx.TimeoutException as e:
                print(f"[bold red]Request Timeout:[/bold red] The request to {e.request.url!r} timed out.")
                # Consider adding retry logic here as well, similar to the 5xx handling
            except httpx.RequestError as e:
                print(f"[bold red]Network Error:[/bold red] An error occurred while requesting {e.request.url!r}.")

            # This part of the original logic is now handled inside the 5xx check
            # but can be kept as a fallback for network errors if desired.
            if attempt < MAX_API_RETRIES - 1:
                backoff_delay = API_RETRY_BASE_DELAY * (2 ** attempt)
                jitter = random.uniform(0, 1)
                delay = backoff_delay + jitter
                print(f"[yellow]Retrying due to network/timeout error in {delay:.2f}s... ({attempt + 1}/{MAX_API_RETRIES})[/yellow]")
                time.sleep(delay)

        raise httpx.RequestError(f"API request failed after {MAX_API_RETRIES} retries.")

    # ... get, post, put methods remain the same ...
    def get(self, endpoint: str, params: dict | None = None) -> Any:
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, json: dict | None = None) -> Any:
        return self._request("POST", endpoint, json=json)

    def put(self, endpoint: str, json: dict | None = None) -> Any:
        return self._request("PUT", endpoint, json=json)