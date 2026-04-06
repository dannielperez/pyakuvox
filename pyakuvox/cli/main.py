"""Main CLI entrypoint — akuvox."""

from __future__ import annotations

import logging
import sys
from typing import Annotated, Optional

import typer

from pyakuvox.cli import output
from pyakuvox.cli.discover_cmd import discover_app
from pyakuvox.cli.local_cmd import local_app
from pyakuvox.cli.raw_cmd import raw_app
from pyakuvox.cli.webui_cmd import webui_app
from pyakuvox.exceptions import AkuvoxError

app = typer.Typer(
    name="akuvox",
    help="Akuvox device management CLI — local API, web UI, and discovery.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

app.add_typer(local_app)
app.add_typer(webui_app)
app.add_typer(discover_app)
app.add_typer(raw_app)


# ── Global callback ─────────────────────────────────────────────────


@app.callback()
def main(
    json_output: Annotated[
        bool, typer.Option("--json", help="Output as JSON instead of human-friendly tables.")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose (DEBUG) logging.")
    ] = False,
    debug_http: Annotated[
        bool,
        typer.Option(
            "--debug-http",
            help="Log full HTTP request/response details (implies --verbose).",
        ),
    ] = False,
) -> None:
    """Akuvox device management CLI."""
    output.set_json_mode(json_output)

    # Configure logging
    from pyakuvox.logging_config import configure_logging

    level = "INFO"
    if verbose or debug_http:
        level = "DEBUG"

    configure_logging(level=level, debug=verbose or debug_http)

    if debug_http:
        logging.getLogger("httpx").setLevel(logging.DEBUG)
        logging.getLogger("httpcore").setLevel(logging.DEBUG)


# ── Capabilities command ────────────────────────────────────────────


@app.command("capabilities")
def capabilities(
    feature: Annotated[
        Optional[str],
        typer.Option("--feature", "-f", help="Filter to a specific feature name."),
    ] = None,
    provider: Annotated[
        Optional[str],
        typer.Option("--provider", "-p", help="Filter to a specific provider (local_http, cloud_official, cloud_reverse_engineered)."),
    ] = None,
) -> None:
    """Show the feature capability matrix across all providers."""
    from pyakuvox.capabilities import Provider, build_default_matrix

    matrix = build_default_matrix()

    if feature:
        caps = matrix.for_feature(feature)
        if not caps:
            output.print_warning(f"No capabilities found for feature '{feature}'.")
            raise typer.Exit(code=1)
    elif provider:
        try:
            p = Provider(provider)
        except ValueError:
            valid = ", ".join(p.value for p in Provider)
            raise typer.BadParameter(f"Unknown provider '{provider}'. Valid: {valid}")
        caps = matrix.for_provider(p)
    else:
        caps = matrix.capabilities

    output.print_model_list(
        caps,
        title="Capability Matrix",
        columns=["feature", "provider", "level", "notes", "source"],
    )


# ── Entrypoint wrapper ─────────────────────────────────────────────


def cli() -> None:
    """Wrapper that catches unexpected AkuvoxError and exits cleanly."""
    try:
        app()
    except AkuvoxError as exc:
        output.print_error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        output.print_error("Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    cli()
