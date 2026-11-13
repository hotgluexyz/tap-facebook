"""Offline Facebook smoke tests with consistent fake account IDs and cursors."""

# ruff: noqa: INP001 -- The harness executes this standalone script by path.

import hashlib
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from faker import Faker
from hotglue_smoke_test.vcr.tap import VCRTapTestRunner


class FacebookTestRunner(VCRTapTestRunner):
    # These replication keys drive incremental filtering and final bookmarks.
    PRESERVE_KEYS = {"created_time", "updated_time"}  # noqa: RUF012
    TOKEN_KEYS = [  # noqa: RUF012
        *VCRTapTestRunner.TOKEN_KEYS,
        "fb_exchange_token",
        "input_token",
        "redirect_uri",
    ]
    # Usage headers contain account IDs; debug/trace headers contain identifiers.
    FILTER_HEADERS = [  # noqa: RUF012
        *VCRTapTestRunner.FILTER_HEADERS,
        "x-business-use-case-usage",
        "x-ad-account-usage",
        "x-app-usage",
        "x-fb-request-id",
        "x-fb-trace-id",
        "x-fb-debug",
        "etag",
    ]

    def module(self) -> str:
        return "tap_facebook"

    def launch(self) -> None:
        from tap_facebook.tap import TapFacebook

        TapFacebook.cli()

    @staticmethod
    def fake_reference(value: str) -> str:
        """Keep account prefixes while consistently replacing opaque references."""
        if value.startswith("act_"):
            return "act_" + FacebookTestRunner.fake_reference(value[4:])
        return "Fake-" + hashlib.sha256(value.encode()).hexdigest()[:24]

    def scrub_uri(self, uri: str) -> str:
        parts = urlsplit(uri)
        path = "/".join(
            self.fake_reference(part) if part.isdigit() or part.startswith("act_") else part
            for part in parts.path.split("/")
        )
        query = [
            (key, self.fake_reference(value) if key in {"after", "before"} else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key.lower() not in {token.lower() for token in self.TOKEN_KEYS}
        ]
        return urlunsplit(parts._replace(path=path, query=urlencode(query)))

    def scrub_response_body(self, body: str, faker: Faker, cache: dict) -> str:
        # Seed the inherited value cache so parent IDs and cursors match the URI
        # scrubber, including the same value reused under a different field name.
        def remember(value: object) -> None:
            if isinstance(value, dict):
                for key, leaf in value.items():
                    if isinstance(leaf, str) and leaf:
                        if key in {"id", "account_id", "after", "before"}:
                            cache[(str, leaf)] = self.fake_reference(leaf)
                        elif key in {"next", "previous"}:
                            cache[(str, leaf)] = self.scrub_uri(leaf)
                    remember(leaf)
            elif isinstance(value, list):
                for item in value:
                    remember(item)

        remember(json.loads(body))
        return super().scrub_response_body(body, faker, cache)


if __name__ == "__main__":
    FacebookTestRunner.main()
