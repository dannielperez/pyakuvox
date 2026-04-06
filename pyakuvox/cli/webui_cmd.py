"""WebUI commands — akuvox webui *."""

from __future__ import annotations

from typing import Annotated

import typer

from pyakuvox.cli.output import print_model, print_success, print_warning, run_async
from pyakuvox.clients.local.webui import FirmwareAuthMode, WebUIClient
from pyakuvox.config import get_settings

webui_app = typer.Typer(name="webui", help="Device web management interface commands.")


def _get_webui_client() -> WebUIClient:
    s = get_settings().local
    return WebUIClient(
        host=s.host,
        port=s.port,
        use_ssl=s.use_ssl,
        verify_ssl=s.verify_ssl,
        timeout=s.timeout,
    )


def _get_creds() -> tuple[str, str]:
    s = get_settings().local
    return s.username, s.password.get_secret_value()


@webui_app.command("login-check")
def login_check() -> None:
    """Verify web UI login credentials."""

    async def _run() -> None:
        username, password = _get_creds()
        async with _get_webui_client() as webui:
            session_id = await webui.login(username, password)
        print_success(f"Login OK — session: {session_id[:8]}…")

    run_async(_run())


@webui_app.command("get-http-api-config")
def get_http_api_config() -> None:
    """Read current HTTP API configuration from the device web UI."""

    async def _run() -> None:
        username, password = _get_creds()
        async with _get_webui_client() as webui:
            await webui.login(username, password)
            cfg = await webui.get_http_api_config()
        print_model(cfg, title="HTTP API Config")

    run_async(_run())


_AUTH_MODE_NAMES = {m.value: m.name for m in FirmwareAuthMode}


@webui_app.command("enable-api")
def enable_api(
    api_username: Annotated[str, typer.Option("--username", "-u", help="API username.")] = "admin",
    api_password: Annotated[str, typer.Option("--password", "-p", help="API password.", prompt=True, hide_input=True)] = ...,  # type: ignore[assignment]
    auth_mode: Annotated[int, typer.Option("--auth-mode", "-m", help="Auth mode (0=none,1=basic,2=whitelist,4=digest). Default: 4.")] = 4,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Configure HTTP API access on the device via the web UI.

    Sets auth mode, username, and password. Default mode is Digest (4),
    which is the most reliable option across tested firmware versions.
    """
    try:
        mode = FirmwareAuthMode(auth_mode)
    except ValueError:
        valid = ", ".join(f"{m.value}={m.name}" for m in FirmwareAuthMode)
        raise typer.BadParameter(f"Invalid auth mode {auth_mode}. Valid: {valid}")

    print_warning(f"This will configure the HTTP API with auth mode: {mode.name} ({mode.value})")
    if not yes:
        typer.confirm("Proceed?", abort=True)

    async def _run() -> None:
        web_username, web_password = _get_creds()
        async with _get_webui_client() as webui:
            await webui.login(web_username, web_password)
            result = await webui.enable_api_access(
                username=api_username,
                password=api_password,
                auth_mode=mode,
            )
        print_model(result, title="Updated HTTP API Config")
        print_success("HTTP API configured.")

    run_async(_run())
