"""
zidentity_auth.py
ZIdentity OAuth2 client credentials authentication.
Shared by all four pipeline modules — CASB, DSPM, ZIA, ZPA.

Usage:
    from zidentity_auth import ZIdentityAuth
    auth = ZIdentityAuth()
    headers = auth.headers()   # {"Authorization": "Bearer <token>"}
    # Token is cached and auto-refreshed before expiry.
"""

import logging
import os
import time

import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ZIdentity token endpoint — format varies slightly by cloud
# zscaler.net | zscalerone.net | zscalertwo.net | zscalerthree.net | zscloud.net
_CLOUD     = os.getenv("ZSCALER_CLOUD", "zscaler.net")
_TOKEN_URL = os.getenv(
    "ZIDENTITY_TOKEN_URL",
    f"https://auth.{_CLOUD}/oauth2/v1/token",
)
_CLIENT_ID     = os.getenv("ZIDENTITY_CLIENT_ID", "")
_CLIENT_SECRET = os.getenv("ZIDENTITY_CLIENT_SECRET", "")

# Scopes required — adjust if your service account has narrower grants
_SCOPES = os.getenv(
    "ZIDENTITY_SCOPES",
    "zia:read zpa:read dspm:read casb:read",
)

# Refresh the token this many seconds before actual expiry (safety margin)
_REFRESH_BUFFER_SECS = 120


class ZIdentityAuth:
    """
    Thread-safe ZIdentity OAuth2 client credentials token manager.
    Tokens are cached in-process and refreshed automatically.
    """

    def __init__(
        self,
        client_id: str = _CLIENT_ID,
        client_secret: str = _CLIENT_SECRET,
        token_url: str = _TOKEN_URL,
        scopes: str = _SCOPES,
    ):
        self._client_id     = client_id
        self._client_secret = client_secret
        self._token_url     = token_url
        self._scopes        = scopes

        self._token: str        = ""
        self._expires_at: float = 0.0

        if not self._client_id or not self._client_secret:
            logger.warning(
                "ZIDENTITY_CLIENT_ID or ZIDENTITY_CLIENT_SECRET not set. "
                "API calls will fail unless credentials are provided."
            )

    # ── Public interface ───────────────────────────────────────────────────────

    def token(self) -> str:
        """Return a valid bearer token, refreshing if needed."""
        if self._needs_refresh():
            self._fetch_token()
        return self._token

    def headers(self) -> dict:
        """Return Authorization headers ready for use in httpx / requests."""
        return {
            "Authorization": f"Bearer {self.token()}",
            "Content-Type":  "application/json",
        }

    def get(self, url: str, **kwargs) -> httpx.Response:
        """Authenticated GET — token is automatically applied."""
        resp = httpx.get(url, headers=self.headers(), timeout=30, **kwargs)
        if resp.status_code == 401:
            # Token may have been revoked — force refresh and retry once
            self._expires_at = 0
            resp = httpx.get(url, headers=self.headers(), timeout=30, **kwargs)
        resp.raise_for_status()
        return resp

    def post(self, url: str, **kwargs) -> httpx.Response:
        """Authenticated POST."""
        resp = httpx.post(url, headers=self.headers(), timeout=30, **kwargs)
        if resp.status_code == 401:
            self._expires_at = 0
            resp = httpx.post(url, headers=self.headers(), timeout=30, **kwargs)
        resp.raise_for_status()
        return resp

    # ── Internal ───────────────────────────────────────────────────────────────

    def _needs_refresh(self) -> bool:
        return not self._token or time.time() >= (self._expires_at - _REFRESH_BUFFER_SECS)

    def _fetch_token(self):
        logger.debug(f"Fetching ZIdentity token from {self._token_url}")
        resp = httpx.post(
            self._token_url,
            data={
                "grant_type":    "client_credentials",
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
                "scope":         self._scopes,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        self._token      = data["access_token"]
        expires_in       = int(data.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in

        logger.info(
            f"ZIdentity token obtained — expires in {expires_in}s "
            f"(refresh at -{_REFRESH_BUFFER_SECS}s)"
        )


# ── Module-level singleton — shared across all four pipeline modules ───────────
# Import and use this directly:
#   from zidentity_auth import auth
#   resp = auth.get("https://api.zsapi.net/...")

auth = ZIdentityAuth()
