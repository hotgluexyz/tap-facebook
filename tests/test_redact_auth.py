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
