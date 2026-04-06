"""Local device commands — akuvox local *."""

from __future__ import annotations

from typing import Annotated, Optional

import typer

from pyakuvox.cli.output import (
    print_dict,
    print_model,
    print_model_list,
    print_success,
    print_warning,
    run_async,
)
from pyakuvox.clients.local import LocalClient
from pyakuvox.config import get_settings

local_app = typer.Typer(name="local", help="Local device HTTP API commands.")
users_app = typer.Typer(name="users", help="User / PIN code management.")
schedules_app = typer.Typer(name="schedules", help="Access schedule management.")
config_app = typer.Typer(name="config", help="Device configuration (autop format).")

local_app.add_typer(users_app)
local_app.add_typer(schedules_app)
local_app.add_typer(config_app)


def _get_client() -> LocalClient:
    settings = get_settings()
    return LocalClient(settings.local)


# ── Device info ─────────────────────────────────────────────────────


@local_app.command("device-info")
def device_info() -> None:
    """Show device identity, firmware, and network info."""

    async def _run() -> None:
        async with _get_client() as client:
            info = await client.get_device_info()
        print_model(info, title="Device Info")

    run_async(_run())


@local_app.command("status")
def status() -> None:
    """Show device operational status (uptime, system time)."""

    async def _run() -> None:
        async with _get_client() as client:
            result = await client.get_device_status()
        print_model(result, title="Device Status")

    run_async(_run())


@local_app.command("firmware")
def firmware() -> None:
    """Show firmware version info."""

    async def _run() -> None:
        async with _get_client() as client:
            info = await client.get_firmware_info()
        print_model(info, title="Firmware Info")

    run_async(_run())


# ── Relay / door control ────────────────────────────────────────────


@local_app.command("relay-status")
def relay_status() -> None:
    """Show current relay states."""

    async def _run() -> None:
        async with _get_client() as client:
            relays = await client.get_relay_status()
        print_model_list(
            relays,
            title="Relay Status",
            columns=["number", "name", "state"],
        )

    run_async(_run())


@local_app.command("unlock")
def unlock(
    relay: Annotated[int, typer.Option("--relay", "-r", help="Relay number (1-based).")] = 1,
    delay: Annotated[int, typer.Option("--delay", "-d", help="Hold time in seconds.")] = 5,
) -> None:
    """Trigger a relay to unlock a door."""

    async def _run() -> None:
        async with _get_client() as client:
            result = await client.trigger_relay(relay_num=relay, delay=delay)
        if result.success:
            print_success(result.message)
        else:
            print_warning(f"Relay trigger failed: {result.message}")
            raise typer.Exit(code=1)

    run_async(_run())


# ── Users ───────────────────────────────────────────────────────────


@users_app.command("list")
def users_list(
    page: Annotated[Optional[int], typer.Option("--page", "-p", help="Page number.")] = None,
) -> None:
    """List user/PIN codes on the device."""

    async def _run() -> None:
        async with _get_client() as client:
            users = await client.list_users(page=page)
        print_model_list(
            users,
            title="Users",
            columns=["id", "name", "user_id", "private_pin", "card_code", "is_cloud_provisioned"],
        )

    run_async(_run())


@users_app.command("list-all")
def users_list_all() -> None:
    """Fetch all users across all pages."""

    async def _run() -> None:
        async with _get_client() as client:
            users = await client.list_all_users()
        print_model_list(
            users,
            title=f"All Users ({len(users)})",
            columns=["id", "name", "user_id", "private_pin", "card_code", "is_cloud_provisioned"],
        )

    run_async(_run())


# ── Schedules ───────────────────────────────────────────────────────


@schedules_app.command("list")
def schedules_list(
    page: Annotated[Optional[int], typer.Option("--page", "-p", help="Page number.")] = None,
) -> None:
    """List access schedules on the device."""

    async def _run() -> None:
        async with _get_client() as client:
            schedules = await client.list_schedules(page=page)
        print_model_list(
            schedules,
            title="Schedules",
            columns=["id", "name", "schedule_type", "time_start", "time_end"],
        )

    run_async(_run())


@schedules_app.command("list-all")
def schedules_list_all() -> None:
    """Fetch all schedules across all pages."""

    async def _run() -> None:
        async with _get_client() as client:
            schedules = await client.list_all_schedules()
        print_model_list(
            schedules,
            title=f"All Schedules ({len(schedules)})",
            columns=["id", "name", "schedule_type", "time_start", "time_end"],
        )

    run_async(_run())


# ── Logs ────────────────────────────────────────────────────────────


@local_app.command("door-logs")
def door_logs(
    all_pages: Annotated[bool, typer.Option("--all", help="Fetch all pages.")] = False,
    page: Annotated[Optional[int], typer.Option("--page", "-p", help="Page number.")] = None,
) -> None:
    """Show door access log entries."""

    async def _run() -> None:
        async with _get_client() as client:
            if all_pages:
                events = await client.list_all_door_logs()
            else:
                events = await client.get_door_logs(page=page)
        print_model_list(
            events,
            title=f"Door Logs ({len(events)})" if all_pages else "Door Logs",
            columns=["date_str", "time_str", "event_type", "user_name", "status"],
        )

    run_async(_run())


@local_app.command("call-logs")
def call_logs(
    all_pages: Annotated[bool, typer.Option("--all", help="Fetch all pages.")] = False,
    page: Annotated[Optional[int], typer.Option("--page", "-p", help="Page number.")] = None,
) -> None:
    """Show call log entries."""

    async def _run() -> None:
        async with _get_client() as client:
            if all_pages:
                events = await client.list_all_call_logs()
            else:
                events = await client.get_call_logs(page=page)
        print_model_list(
            events,
            title=f"Call Logs ({len(events)})" if all_pages else "Call Logs",
            columns=["date_str", "time_str", "caller_name", "call_type", "count"],
        )

    run_async(_run())


# ── Config ──────────────────────────────────────────────────────────


@config_app.command("get")
def config_get() -> None:
    """Dump full device configuration (autop format)."""

    async def _run() -> None:
        async with _get_client() as client:
            cfg = await client.get_config()
        print_dict(cfg, title="Device Config")

    run_async(_run())


@config_app.command("set")
def config_set(
    pairs: Annotated[
        list[str],
        typer.Argument(help="Key=value pairs to set (e.g. SIP.Port=5060)."),
    ],
) -> None:
    """Set device configuration values.

    Pass one or more key=value arguments.  For example:

        akuvox local config set SIP.Port=5060 SIP.Enable=1
    """
    settings_dict: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            print_warning(f"Skipping invalid pair (missing '='): {pair}")
            continue
        key, _, value = pair.partition("=")
        settings_dict[key.strip()] = value.strip()

    if not settings_dict:
        raise typer.BadParameter("No valid key=value pairs provided.")

    async def _run() -> None:
        async with _get_client() as client:
            await client.set_config(settings_dict)
        print_success(f"Set {len(settings_dict)} config value(s).")

    run_async(_run())


# ── Reboot ──────────────────────────────────────────────────────────


@local_app.command("reboot")
def reboot(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Reboot the device (experimental / unverified endpoint)."""
    print_warning("Reboot endpoint is UNVERIFIED — may not work on all firmware.")
    if not yes:
        typer.confirm("Proceed with reboot?", abort=True)

    async def _run() -> None:
        async with _get_client() as client:
            ok = await client.reboot()
        if ok:
            print_success("Reboot command sent.")
        else:
            print_warning("Reboot command may have failed — check device.")
            raise typer.Exit(code=1)

    run_async(_run())
