"""Raw HTTP commands — akuvox raw *."""

from __future__ import annotations

import json
from typing import Annotated, Optional

import typer

from pyakuvox.cli.output import print_dict, run_async
from pyakuvox.clients.local import LocalClient
from pyakuvox.config import get_settings

raw_app = typer.Typer(name="raw", help="Raw HTTP requests for endpoint exploration / research.")


def _get_client() -> LocalClient:
    return LocalClient(get_settings().local)


@raw_app.command("get")
def raw_get(
    path: Annotated[str, typer.Argument(help="API path, e.g. /api/system/info")],
    param: Annotated[Optional[list[str]], typer.Option("--param", "-q", help="Query params as key=value.")] = None,
) -> None:
    """Make a raw GET request to the device.

    Useful for exploring undocumented endpoints.
    """
    params: dict[str, str] = {}
    for p in param or []:
        if "=" in p:
            k, _, v = p.partition("=")
            params[k.strip()] = v.strip()

    async def _run() -> None:
        async with _get_client() as client:
            data = await client.raw_get(path, **params)
        print_dict(data, title=f"GET {path}")

    run_async(_run())


@raw_app.command("post")
def raw_post(
    path: Annotated[str, typer.Argument(help="API path, e.g. /api/relay/trigger")],
    body: Annotated[Optional[str], typer.Option("--body", "-b", help="JSON body string.")] = None,
    body_file: Annotated[Optional[str], typer.Option("--body-file", "-f", help="Path to JSON file for request body.")] = None,
) -> None:
    """Make a raw POST request to the device.

    Provide a JSON body via --body or --body-file.
    """
    json_body: dict[str, object] = {}
    if body:
        try:
            json_body = json.loads(body)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"Invalid JSON body: {exc}")
    elif body_file:
        try:
            with open(body_file) as f:
                json_body = json.loads(f.read())
        except (OSError, json.JSONDecodeError) as exc:
            raise typer.BadParameter(f"Cannot read body file: {exc}")

    async def _run() -> None:
        async with _get_client() as client:
            data = await client.raw_post(path, json_body)
        print_dict(data, title=f"POST {path}")

    run_async(_run())
