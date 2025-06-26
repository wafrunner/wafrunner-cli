import pytest
import httpx
import time

from wafrunner_cli.core.api_client import ApiClient
from wafrunner_cli.core.exceptions import AuthenticationError


def test_api_client_initialization_no_token(mocker):
    """
    Verify that AuthenticationError is raised if the config manager finds no token.
    """
    # Arrange: Mock ConfigManager to return None for the token
    mocker.patch(
        "wafrunner_cli.core.api_client.ConfigManager.load_token", return_value=None
    )

    # Act & Assert: Check that initializing the client raises the correct error
    with pytest.raises(AuthenticationError, match="API token not found"):
        ApiClient()


def test_api_client_get_success(mocker):
    """
    Verify that a successful GET request returns the expected JSON data.
    """
    # Arrange: Mock a valid token and a successful httpx response
    mocker.patch(
        "wafrunner_cli.core.api_client.ConfigManager.load_token",
        return_value="fake-token",
    )
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "success"}

    # We now mock the internal _request method for simplicity in some tests
    mock_request = mocker.patch("wafrunner_cli.core.api_client.ApiClient._request")
    mock_request.return_value = mock_response

    # Act
    api_client = ApiClient()
    result = api_client.get("/test-endpoint")

    # Assert
    assert result == {"data": "success"}
    mock_request.assert_called_once_with("GET", "/test-endpoint", params=None)


def test_api_client_get_not_found_returns_none(mocker):
    """
    Verify that a 404 response from a GET request returns None without raising an error.
    """
    mocker.patch(
        "wafrunner_cli.core.api_client.ConfigManager.load_token",
        return_value="fake-token",
    )
    mock_response = mocker.Mock()
    mock_response.status_code = 404

    mocker.patch(
        "wafrunner_cli.core.api_client.ApiClient._request", return_value=mock_response
    )

    # Act
    api_client = ApiClient()
    result = api_client.get("/not-found-endpoint")

    # Assert
    assert result is None


def test_api_client_retries_on_server_error(mocker):
    """
    Verify that the client retries on a 500 error and eventually succeeds.
    """
    mocker.patch(
        "wafrunner_cli.core.api_client.ConfigManager.load_token",
        return_value="fake-token",
    )
    # Mock time.sleep to avoid actual delays in the test
    mock_sleep = mocker.patch("wafrunner_cli.core.api_client.time.sleep")

    # Simulate a 500 error, then a 200 success
    response_500 = httpx.Response(500, json={"detail": "Internal Server Error"})
    response_200 = httpx.Response(200, json={"data": "finally success"})

    mock_request_method = mocker.patch(
        "wafrunner_cli.core.api_client.httpx.Client.request",
        side_effect=[response_500, response_200],
    )

    # Act
    api_client = ApiClient()
    result = api_client.get("/flaky-endpoint")

    # Assert
    assert result == {"data": "finally success"}
    assert mock_request_method.call_count == 2
    mock_sleep.assert_called_once()


def test_api_client_fails_after_all_retries(mocker):
    """
    Verify that the client raises an exception after all retries have failed.
    """
    mocker.patch(
        "wafrunner_cli.core.api_client.ConfigManager.load_token",
        return_value="fake-token",
    )
    mocker.patch("wafrunner_cli.core.api_client.time.sleep")

    # Simulate a persistent 503 error
    response_503 = httpx.Response(503, json={"detail": "Service Unavailable"})
    mocker.patch(
        "wafrunner_cli.core.api_client.httpx.Client.request", return_value=response_503
    )

    # Act & Assert
    with pytest.raises(httpx.RequestError, match="API request failed after 3 retries"):
        api_client = ApiClient()
        api_client.get("/non-existent-endpoint")