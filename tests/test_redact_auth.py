"""Tests for OAuth error redaction."""

from unittest.mock import MagicMock

import pytest
import requests

from tap_facebook.auth import OAuth2Authenticator

_CLIENT_SECRET = "qwertyuiop1234567890asdfghjkl"
_CLIENT_ID = "zxcvbnm1234567890lkjhgfdsa"
_ACCESS_TOKEN = "1QAZ2WSX3EDC4RFV5TGB6YHN7UJM8IK9OL0P"

_HTTP_ERROR_URL = (
    "400 Client Error: Bad Request for url: "
    "https://graph.facebook.com/v24.0/oauth/access_token?"
    f"fb_exchange_token={_ACCESS_TOKEN}&grant_type=fb_exchange_token"
    f"&client_id={_CLIENT_ID}&client_secret={_CLIENT_SECRET}"
)


@pytest.fixture
def authenticator():
    tap = MagicMock()
    tap._config = {
        "access_token": _ACCESS_TOKEN,
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
    }
    tap.config = tap._config
    stream = MagicMock()
    stream._tap = tap
    return OAuth2Authenticator(
        stream,
        auth_endpoint="https://graph.facebook.com/v24.0/oauth/access_token",
    )


def test_redact_oauth_exception_masks_url_params(authenticator):
    exc = requests.HTTPError(_HTTP_ERROR_URL)

    redacted = authenticator._redact_oauth_exception(exc)

    assert _CLIENT_SECRET not in redacted
    assert _ACCESS_TOKEN not in redacted
    assert f"client_secret={_CLIENT_SECRET[:5]}***{_CLIENT_SECRET[-5:]}" in redacted
    assert f"client_id={_CLIENT_ID[:5]}***{_CLIENT_ID[-5:]}" in redacted
    assert (
        f"fb_exchange_token={_ACCESS_TOKEN[:10]}***{_ACCESS_TOKEN[-10:]}" in redacted
    )


def test_redact_oauth_exception_leaves_short_values_unchanged(authenticator):
    exc = requests.HTTPError("error for url: https://example.com?client_id=12345")

    redacted = authenticator._redact_oauth_exception(exc)

    assert "client_id=12345" in redacted


def test_redact_oauth_exception_masks_debug_token_params(authenticator):
    exc = requests.HTTPError(
        "400 Client Error for url: https://graph.facebook.com/v24.0/debug_token?"
        f"input_token={_ACCESS_TOKEN}&access_token={_CLIENT_ID}|{_CLIENT_SECRET}"
    )

    redacted = authenticator._redact_oauth_exception(exc)

    assert _ACCESS_TOKEN not in redacted
    assert f"input_token={_ACCESS_TOKEN[:10]}***{_ACCESS_TOKEN[-10:]}" in redacted


def test_is_token_valid_without_expires_at(authenticator):
    assert authenticator.is_token_valid() is False


def test_is_token_valid_with_expires_at(authenticator, monkeypatch):
    from datetime import datetime

    now = round(datetime.utcnow().timestamp())
    authenticator._tap.config["expires_at"] = now + 864000 * 2
    assert authenticator.is_token_valid() is True

    authenticator._tap.config["expires_at"] = now + 864000 // 2
    assert authenticator.is_token_valid() is False


def test_update_access_token_without_expires_in(authenticator, monkeypatch, tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text("{}")
    authenticator._tap.config_file = str(config_file)

    data_access_expires_at = 1893456000

    token_response = MagicMock()
    token_response.json.return_value = {
        "access_token": "new-token",
        "token_type": "bearer",
    }
    token_response.raise_for_status.return_value = None

    debug_response = MagicMock()
    debug_response.json.return_value = {
        "data": {
            "data_access_expires_at": data_access_expires_at,
            "is_valid": True,
        }
    }
    debug_response.raise_for_status.return_value = None

    def mock_get(url, *args, **kwargs):
        if "debug_token" in url:
            return debug_response
        return token_response

    monkeypatch.setattr("tap_facebook.auth.requests.get", mock_get)

    authenticator.update_access_token()

    assert authenticator._tap._config["access_token"] == "new-token"
    assert authenticator._tap._config["expires_at"] == data_access_expires_at


def test_update_access_token_with_expires_in(authenticator, monkeypatch, tmp_path):
    from datetime import datetime

    config_file = tmp_path / "config.json"
    config_file.write_text("{}")
    authenticator._tap.config_file = str(config_file)

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "access_token": "new-token",
        "token_type": "bearer",
        "expires_in": 5183996,
    }
    mock_response.raise_for_status.return_value = None
    monkeypatch.setattr(
        "tap_facebook.auth.requests.get",
        lambda *args, **kwargs: mock_response,
    )

    before = round(datetime.utcnow().timestamp())
    authenticator.update_access_token()
    after = round(datetime.utcnow().timestamp())

    assert authenticator._tap._config["access_token"] == "new-token"
    assert before + 5183996 <= authenticator._tap._config["expires_at"] <= after + 5183996


def test_update_access_token_redacts_debug_token_exception(
    authenticator, monkeypatch, tmp_path
):
    config_file = tmp_path / "config.json"
    config_file.write_text("{}")
    authenticator._tap.config_file = str(config_file)

    token_response = MagicMock()
    token_response.json.return_value = {
        "access_token": _ACCESS_TOKEN,
        "token_type": "bearer",
    }
    token_response.raise_for_status.return_value = None

    debug_error_url = (
        "400 Client Error for url: https://graph.facebook.com/v24.0/debug_token?"
        f"input_token={_ACCESS_TOKEN}&access_token={_CLIENT_ID}|{_CLIENT_SECRET}"
    )
    debug_response = MagicMock()
    debug_response.json.return_value = {
        "error": {"message": "Invalid token", "code": 100}
    }
    debug_response.raise_for_status.side_effect = requests.HTTPError(debug_error_url)

    def mock_get(url, *args, **kwargs):
        if "debug_token" in url:
            return debug_response
        return token_response

    monkeypatch.setattr("tap_facebook.auth.requests.get", mock_get)

    with pytest.raises(RuntimeError) as exc_info:
        authenticator.update_access_token()

    message = str(exc_info.value)
    assert _CLIENT_SECRET not in message
    assert _ACCESS_TOKEN not in message
    assert f"input_token={_ACCESS_TOKEN[:10]}***{_ACCESS_TOKEN[-10:]}" in message
    assert exc_info.value.__cause__ is None


def test_update_access_token_redacts_exception_and_suppresses_cause(
    authenticator, monkeypatch
):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "error": {
            "message": "Error validating client secret.",
            "type": "OAuthException",
            "code": 1,
            "fbtrace_id": "ACCr-g33JNYO7Va6C45XX5_",
        }
    }
    mock_response.raise_for_status.side_effect = requests.HTTPError(_HTTP_ERROR_URL)
    monkeypatch.setattr(
        "tap_facebook.auth.requests.get",
        lambda *args, **kwargs: mock_response,
    )

    with pytest.raises(RuntimeError) as exc_info:
        authenticator.update_access_token()

    message = str(exc_info.value)
    assert _CLIENT_SECRET not in message
    assert _ACCESS_TOKEN not in message
    assert f"client_secret={_CLIENT_SECRET[:5]}***{_CLIENT_SECRET[-5:]}" in message
    assert exc_info.value.__cause__ is None
