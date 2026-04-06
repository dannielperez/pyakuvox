"""CLI output formatting — human-friendly tables or JSON."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from collections.abc import Coroutine
from typing import Any

import typer
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pyakuvox.exceptions import (
    AkuvoxError,
    AuthenticationError,
    CloudNotConfiguredError,
    ConnectionError,
    ParseError,
    TimeoutError,
    UnsupportedFeatureError,
)

console = Console(stderr=False)
err_console = Console(stderr=True)

# Module-level state set by the main callback.
_json_mode: bool = False


def set_json_mode(enabled: bool) -> None:
    global _json_mode
    _json_mode = enabled


def is_json_mode() -> bool:
    return _json_mode


# ── Error-handling async runner ─────────────────────────────────────

_EXIT_CODES: dict[type[AkuvoxError], int] = {
    AuthenticationError: 2,
    ConnectionError: 3,
    TimeoutError: 4,
    ParseError: 5,
    UnsupportedFeatureError: 6,
    CloudNotConfiguredError: 7,
}


def run_async(coro: Coroutine[Any, Any, Any]) -> None:
    """Run an async coroutine with AkuvoxError → CLI exit-code mapping."""
    try:
        asyncio.run(coro)
    except AkuvoxError as exc:
        for exc_type, code in _EXIT_CODES.items():
            if isinstance(exc, exc_type):
                print_error(str(exc))
                raise typer.Exit(code=code)
        print_error(str(exc))
        raise typer.Exit(code=1)


# ── Serialisation helpers ───────────────────────────────────────────


def _to_dict(obj: Any) -> Any:
    """Convert a model/dataclass/dict to a JSON-serialisable dict."""
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    return obj


# ── Public output functions ─────────────────────────────────────────


def print_json(data: Any) -> None:
    """Print data as formatted JSON to stdout."""
    console.print_json(json.dumps(_to_dict(data), default=str))


def print_record(data: dict[str, Any], *, title: str = "") -> None:
    """Print a single record as a key-value panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan", no_wrap=True)
    table.add_column("Value")
    for key, value in data.items():
        table.add_row(key, _fmt(value))
    if title:
        console.print(Panel(table, title=title, border_style="blue"))
    else:
        console.print(table)


def print_table(rows: list[dict[str, Any]], *, title: str = "", columns: list[str] | None = None) -> None:
    """Print a list of records as a rich table."""
    if not rows:
        console.print("[dim]No results.[/dim]")
        return
    cols = columns or list(rows[0].keys())
    table = Table(title=title, show_lines=False)
    for col in cols:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*(str(row.get(c, "")) for c in cols))
    console.print(table)


def print_model(obj: BaseModel | Any, *, title: str = "") -> None:
    """Auto-dispatch: JSON mode → json, else key-value panel."""
    if _json_mode:
        print_json(obj)
        return
    data = _to_dict(obj)
    if isinstance(data, dict):
        # Flatten nested identity for DeviceInfo
        if "identity" in data and isinstance(data["identity"], dict):
            identity = data.pop("identity")
            data = {**identity, **data}
        print_record(data, title=title)
    elif isinstance(data, list):
        if data and isinstance(data[0], dict):
            print_table(data, title=title)
        else:
            for item in data:
                console.print(str(item))
    else:
        console.print(str(data))


def print_model_list(items: list[Any], *, title: str = "", columns: list[str] | None = None) -> None:
    """Print a list of models as a table or JSON array."""
    if _json_mode:
        print_json(items)
        return
    rows = [_to_dict(item) for item in items]
    print_table(rows, title=title, columns=columns)


def print_dict(data: dict[str, Any], *, title: str = "") -> None:
    """Print a raw dict."""
    if _json_mode:
        print_json(data)
        return
    print_record(data, title=title)


def print_success(message: str) -> None:
    if _json_mode:
        print_json({"status": "ok", "message": message})
    else:
        console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    err_console.print(f"[yellow]⚠[/yellow] {message}", style="yellow")


def print_error(message: str) -> None:
    err_console.print(f"[red]✗[/red] {message}", style="red")


def _fmt(value: Any) -> str:
    """Format a value for human display."""
    if value is None:
        return "[dim]—[/dim]"
    if isinstance(value, bool):
        return "[green]yes[/green]" if value else "[red]no[/red]"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "[dim]—[/dim]"
    if isinstance(value, dict):
        return json.dumps(value, default=str)
    return str(value)
