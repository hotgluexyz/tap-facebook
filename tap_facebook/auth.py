import json
from datetime import datetime
from typing import Optional

import requests
from singer_sdk.authenticators import APIAuthenticatorBase
from singer_sdk.streams import Stream as RESTStreamBase
import backoff
from http.client import RemoteDisconnected
from requests.exceptions import ConnectionError

class EmptyResponseError(Exception):
    """Raised when the response is empty"""

class OAuth2Authenticator(APIAuthenticatorBase):
    def __init__(
        self,
        stream: RESTStreamBase,
        config_file: Optional[str] = None,
        auth_endpoint: Optional[str] = None,
    ) -> None:
        super().__init__(stream=stream)
        self._auth_endpoint = auth_endpoint
        self._config_file = config_file
        self._tap = stream._tap

    @property
    def auth_headers(self) -> dict:
        if not self.is_token_valid():
            self.update_access_token()
        result = super().auth_headers
        result["Authorization"] = f"Bearer {self._tap._config.get('access_token')}"
        return result

    @property
    def oauth_request_body(self) -> dict:
        """Define the OAuth request body for the hubspot API."""
        return {
            "fb_exchange_token": self._tap._config["access_token"],
            "grant_type": "fb_exchange_token",
            "client_id": self._tap._config["client_id"],
            "client_secret": self._tap._config["client_secret"],
        }

    def is_token_valid(self) -> bool:
        access_token = self._tap._config.get("access_token")
        now = round(datetime.utcnow().timestamp())
        expires_in = self._tap.config.get("expires_at")
        if expires_in is not None:
            expires_in = int(expires_in)
        if not access_token:
            return False

        if not expires_in:
            return False
        # token can only be refreshed if previous token hasn't expired, refresh 10 days before expiration in case tap is not running often enough
        return not ((expires_in - now) < 864000) # 10 days in seconds

    @backoff.on_exception(backoff.expo,(EmptyResponseError, RemoteDisconnected, ConnectionError),max_tries=5,factor=3)
    def update_access_token(self) -> None:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_response = requests.get(
            self._auth_endpoint, params=self.oauth_request_body, headers=headers
        )

        try:
            token_response.raise_for_status()
            self.logger.info("OAuth authorization attempt was successful.")
        except Exception as ex:
            raise RuntimeError(
                f"Failed OAuth login, response was '{token_response.json()}'. {ex}"
            )
        token_json = token_response.json()

        self.access_token = token_json["access_token"]

        self._tap._config["access_token"] = token_json["access_token"]
        now = round(datetime.utcnow().timestamp())
        self._tap._config["expires_at"] = int(token_json["expires_in"]) + now

        with open(self._tap.config_file, "w") as outfile:
            json.dump(self._tap._config, outfile, indent=4)
