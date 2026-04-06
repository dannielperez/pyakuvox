"""Discovery commands — akuvox discover *."""

from __future__ import annotations

from typing import Annotated, Optional

import typer

from pyakuvox.cli.output import is_json_mode, print_model_list, print_warning, run_async
from pyakuvox.discovery import scan_targets

discover_app = typer.Typer(name="discover", help="Network discovery for Akuvox devices.")


@discover_app.command("scan")
def scan(
    targets: Annotated[
        list[str],
        typer.Argument(help="IP addresses, CIDR ranges, or hyphenated ranges to scan."),
    ],
    port: Annotated[int, typer.Option("--port", help="TCP port to probe.")] = 80,
    username: Annotated[Optional[str], typer.Option("--username", "-u", help="Credentials for pulling full device info.")] = None,
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Credentials for pulling full device info.")] = None,
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="TCP connect timeout in seconds.")] = 1.0,
    concurrency: Annotated[int, typer.Option("--concurrency", "-c", help="Max concurrent probes.")] = 50,
) -> None:
    """Scan a network for Akuvox devices.

    Examples:

        akuvox discover scan 192.168.1.0/24

        akuvox discover scan 10.0.0.1-50 --username admin --password admin
    """
    if not is_json_mode():
        print_warning("Scanning... this may take a moment for large ranges.")

    async def _run() -> None:
        devices = await scan_targets(
            targets=targets,
            username=username,
            password=password,
            ports=[port],
            tcp_timeout=timeout,
            max_concurrent=concurrency,
        )
        print_model_list(
            devices,
            title=f"Discovered Devices ({len(devices)})",
            columns=["ip", "port", "model", "mac_address", "firmware_version", "authenticated"],
        )

    run_async(_run())
