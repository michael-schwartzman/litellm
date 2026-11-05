import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError

from .common_utils import GetAPIKeyError

GITHUB_APP_ID_ENV: Final = "GITHUB_COPILOT_APP_ID"
GITHUB_APP_INSTALLATION_ID_ENV: Final = "GITHUB_COPILOT_APP_INSTALLATION_ID"
GITHUB_APP_PRIVATE_KEY_ENV: Final = "GITHUB_COPILOT_APP_PRIVATE_KEY"
GITHUB_APP_PRIVATE_KEY_PATH_ENV: Final = "GITHUB_COPILOT_APP_PRIVATE_KEY_PATH"
GITHUB_APP_API_URL_ENV: Final = "GITHUB_COPILOT_APP_API_URL"
_GITHUB_APP_ENV_VARS: Final = (
    GITHUB_APP_ID_ENV,
    GITHUB_APP_INSTALLATION_ID_ENV,
    GITHUB_APP_PRIVATE_KEY_ENV,
    GITHUB_APP_PRIVATE_KEY_PATH_ENV,
)

DEFAULT_GITHUB_API_URL: Final = "https://api.github.com"
_REFRESH_MARGIN_SECONDS: Final = 300
_APP_JWT_BACKDATE_SECONDS: Final = 60
_APP_JWT_LIFETIME_SECONDS: Final = 540


@dataclass(frozen=True, slots=True)
class GithubAppInstallation:
    app_id: str
    installation_id: str
    private_key: str
    api_url: str


@dataclass(frozen=True, slots=True)
class InstallationToken:
    token: str
    expires_at: float


class _AccessTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", hide_input_in_errors=True)

    token: str
    expires_at: datetime


def github_app_auth_configured() -> bool:
    return any(os.getenv(name) for name in _GITHUB_APP_ENV_VARS)


def _read_private_key(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError as e:
        raise GetAPIKeyError(
            status_code=500,
            message=f"Could not read the GitHub App private key from {GITHUB_APP_PRIVATE_KEY_PATH_ENV}: {e.strerror}",
        ) from e


def github_app_installation_from_env() -> GithubAppInstallation | None:
    if not github_app_auth_configured():
        return None
    key_path: Final = os.getenv(GITHUB_APP_PRIVATE_KEY_PATH_ENV)
    private_key: Final = os.getenv(GITHUB_APP_PRIVATE_KEY_ENV) or (_read_private_key(key_path) if key_path else "")
    app_id: Final = os.getenv(GITHUB_APP_ID_ENV, "")
    installation_id: Final = os.getenv(GITHUB_APP_INSTALLATION_ID_ENV, "")
    missing: Final = tuple(
        name
        for name, value in (
            (GITHUB_APP_ID_ENV, app_id),
            (GITHUB_APP_INSTALLATION_ID_ENV, installation_id),
            (f"{GITHUB_APP_PRIVATE_KEY_ENV} or {GITHUB_APP_PRIVATE_KEY_PATH_ENV}", private_key),
        )
        if not value
    )
    if missing:
        raise GetAPIKeyError(
            status_code=500,
            message=f"GitHub App auth for GitHub Copilot is partially configured, set {', '.join(missing)}",
        )
    return GithubAppInstallation(
        app_id=app_id,
        installation_id=installation_id,
        private_key=private_key.replace("\\n", "\n"),
        api_url=os.getenv(GITHUB_APP_API_URL_ENV, DEFAULT_GITHUB_API_URL).rstrip("/"),
    )


def _app_jwt(installation: GithubAppInstallation, now: float) -> str:
    try:
        import jwt
    except ImportError as e:
        raise GetAPIKeyError(
            status_code=500,
            message="GitHub App auth for GitHub Copilot needs PyJWT, install it with `pip install 'PyJWT[crypto]'`",
        ) from e
    try:
        return jwt.encode(
            {
                "iat": int(now) - _APP_JWT_BACKDATE_SECONDS,
                "exp": int(now) + _APP_JWT_LIFETIME_SECONDS,
                "iss": installation.app_id,
            },
            installation.private_key,
            algorithm="RS256",
        )
    except (jwt.PyJWTError, ValueError, TypeError) as e:
        raise GetAPIKeyError(
            status_code=500,
            message=f"Could not sign a GitHub App JWT, check the private key: {type(e).__name__}",
        ) from e


def mint_installation_token(installation: GithubAppInstallation, client: httpx.Client, now: float) -> InstallationToken:
    url: Final = f"{installation.api_url}/app/installations/{installation.installation_id}/access_tokens"
    try:
        response: Final = client.post(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {_app_jwt(installation, now)}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"permissions": {"organization_copilot_requests": "read"}},
        ).raise_for_status()
        parsed: Final = _AccessTokenResponse.model_validate_json(response.content)
    except httpx.HTTPStatusError as e:
        raise GetAPIKeyError(
            status_code=401,
            message=f"GitHub refused an installation token for installation {installation.installation_id}: "
            f"HTTP {e.response.status_code}",
        ) from e
    except (httpx.HTTPError, ValidationError) as e:
        raise GetAPIKeyError(
            status_code=401,
            message=f"Could not get a GitHub App installation token: {type(e).__name__}",
        ) from e
    return InstallationToken(token=parsed.token, expires_at=parsed.expires_at.timestamp())


class InstallationTokenCache:
    def __init__(
        self,
        client_factory: Callable[[], httpx.Client],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client_factory: Final = client_factory
        self._clock: Final = clock
        self._lock: Final = threading.Lock()
        self._tokens: Final[dict[GithubAppInstallation, InstallationToken]] = {}  # mutable-ok: token cache

    def token(self, installation: GithubAppInstallation) -> str:
        with self._lock:
            now: Final = self._clock()
            cached: Final = self._tokens.get(installation)
            if cached is not None and cached.expires_at - _REFRESH_MARGIN_SECONDS > now:
                return cached.token
            fresh: Final = mint_installation_token(installation, self._client_factory(), now)
            self._tokens[installation] = fresh
            return fresh.token

