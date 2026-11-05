import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from litellm.llms.github_copilot.app_installation_auth import InstallationTokenCache
from litellm.llms.github_copilot.authenticator import Authenticator
from litellm.llms.github_copilot.chat.transformation import GithubCopilotConfig
from litellm.llms.github_copilot.common_utils import GetAPIKeyError

APP_ID: Final = "5626339"
INSTALLATION_ID: Final = "178889411"
TOKEN_URL: Final = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
NOW: Final = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc).timestamp()
EXPIRES_AT: Final = "2030-01-01T13:00:00Z"
_RSA_KEY: Final = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_KEY_PEM: Final = _RSA_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GITHUB_COPILOT_TOKEN_DIR", str(tmp_path))
    monkeypatch.setenv("GITHUB_COPILOT_APP_ID", APP_ID)
    monkeypatch.setenv("GITHUB_COPILOT_APP_INSTALLATION_ID", INSTALLATION_ID)
    monkeypatch.setenv("GITHUB_COPILOT_APP_PRIVATE_KEY", PRIVATE_KEY_PEM)
    return tmp_path


def _authenticator(clock: _Clock) -> Authenticator:
    return Authenticator(installation_tokens=InstallationTokenCache(clock=clock))


def test_app_auth_mints_a_copilot_scoped_installation_token_signed_by_the_app(app_env: Path) -> None:
    with respx.mock(assert_all_called=True) as router:
        route: Final = router.post(TOKEN_URL).respond(json={"token": "ghs_minted", "expires_at": EXPIRES_AT})
        assert _authenticator(_Clock(NOW)).get_api_key() == "ghs_minted"

    request: Final = route.calls.last.request
    assert json.loads(request.content) == {"permissions": {"organization_copilot_requests": "read"}}
    scheme, app_jwt = request.headers["authorization"].split(" ")
    assert scheme == "Bearer"
    claims: Final = jwt.decode(
        app_jwt, _RSA_KEY.public_key(), algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False}
    )
    assert claims["iss"] == APP_ID
    assert claims["iat"] <= NOW < claims["exp"]


def test_app_auth_never_touches_the_device_flow_files(app_env: Path) -> None:
    (app_env / "api-key.json").write_text(
        json.dumps({"token": "tid=user", "expires_at": NOW + 3600, "endpoints": {"api": "https://user.example"}})
    )
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).respond(json={"token": "ghs_minted", "expires_at": EXPIRES_AT})
        authenticator: Final = _authenticator(_Clock(NOW))
        assert authenticator.get_api_key() == "ghs_minted"

    assert authenticator.get_api_base() is None


def test_installation_token_is_reused_until_it_nears_expiry(app_env: Path) -> None:
    clock: Final = _Clock(NOW)
    authenticator: Final = _authenticator(clock)
    with respx.mock(assert_all_called=True) as router:
        route: Final = router.post(TOKEN_URL)
        route.side_effect = [
            respx.MockResponse(201, json={"token": "ghs_first", "expires_at": EXPIRES_AT}),
            respx.MockResponse(201, json={"token": "ghs_second", "expires_at": "2030-01-01T14:00:00Z"}),
        ]
        assert authenticator.get_api_key() == "ghs_first"
        clock.now = NOW + 3600 - 301
        assert authenticator.get_api_key() == "ghs_first"
        clock.now = NOW + 3600 - 299
        assert authenticator.get_api_key() == "ghs_second"

    assert route.call_count == 2


def test_private_key_can_come_from_a_file(app_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file: Final = app_env / "app.pem"
    key_file.write_text(PRIVATE_KEY_PEM)
    monkeypatch.delenv("GITHUB_COPILOT_APP_PRIVATE_KEY")
    monkeypatch.setenv("GITHUB_COPILOT_APP_PRIVATE_KEY_PATH", str(key_file))
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).respond(json={"token": "ghs_from_file", "expires_at": EXPIRES_AT})
        assert _authenticator(_Clock(NOW)).get_api_key() == "ghs_from_file"


def test_private_key_with_escaped_newlines_still_signs(app_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_COPILOT_APP_PRIVATE_KEY", PRIVATE_KEY_PEM.replace("\n", "\\n"))
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).respond(json={"token": "ghs_escaped", "expires_at": EXPIRES_AT})
        assert _authenticator(_Clock(NOW)).get_api_key() == "ghs_escaped"


def test_partial_app_config_fails_instead_of_falling_back_to_device_login(
    app_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (app_env / "access-token").write_text("gho_logged_in")
    monkeypatch.delenv("GITHUB_COPILOT_APP_INSTALLATION_ID")
    with respx.mock(assert_all_called=False) as router, pytest.raises(GetAPIKeyError) as exc:
        _authenticator(_Clock(NOW)).get_api_key()

    assert "GITHUB_COPILOT_APP_INSTALLATION_ID" in exc.value.message
    assert not router.calls


@pytest.mark.parametrize("status", [401, 403, 404])
def test_github_refusing_the_token_is_an_auth_error(app_env: Path, status: int) -> None:
    with respx.mock(assert_all_called=True) as router, pytest.raises(GetAPIKeyError) as exc:
        router.post(TOKEN_URL).respond(status, json={"message": "nope"})
        _authenticator(_Clock(NOW)).get_api_key()

    assert exc.value.status_code == 401
    assert str(status) in exc.value.message


def test_chat_requests_carry_the_installation_token_under_the_sdk_integration_id(
    app_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_COPILOT_APP_INSTALLATION_ID", "4242")
    config: Final = GithubCopilotConfig()
    with respx.mock(assert_all_called=True) as router:
        router.post("https://api.github.com/app/installations/4242/access_tokens").respond(
            json={"token": "ghs_minted", "expires_at": EXPIRES_AT}
        )
        api_base, api_key, _ = config.get_openai_compatible_provider_info("gpt-4.1", None, None, "github_copilot")
        headers: Final = config.validate_environment(
            {}, "gpt-4.1", [{"role": "user", "content": "hi"}], {}, {}, api_key, api_base
        )

    assert api_key == "ghs_minted"
    assert headers["Authorization"] == "Bearer ghs_minted"
    assert headers["copilot-integration-id"] == "copilot-developer-cli"


def test_user_tokens_keep_the_vscode_integration_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_COPILOT_TOKEN_DIR", str(tmp_path))
    (tmp_path / "api-key.json").write_text(json.dumps({"token": "tid=user", "expires_at": 4102444800}))
    config: Final = GithubCopilotConfig()
    api_base, api_key, _ = config.get_openai_compatible_provider_info("gpt-4.1", None, None, "github_copilot")
    headers: Final = config.validate_environment(
        {}, "gpt-4.1", [{"role": "user", "content": "hi"}], {}, {}, api_key, api_base
    )

    assert headers["copilot-integration-id"] == "vscode-chat"
