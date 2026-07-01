"""Universal "set the HTTP-API auth mode" orchestrator.

Akuvox ships several mutually-incompatible web UIs (FCGI ``/fcgi/do`` for
X916/R29C, the SPA ``/api/web/*`` for S5xx), and each encodes the API password
differently. Locked panels (HTTP-API auth = WhiteList with an empty allowlist)
answer ``403`` to the digest ``/api`` that :class:`LocalClient` needs.

:func:`enable_api` is the one entry point that reconfigures a panel's HTTP-API
auth regardless of model/firmware. The ``auth_mode`` flag makes it generic — the
common case is Digest (so :class:`LocalClient` can drive the panel headlessly),
but the same call sets WhiteList, None, or Basic+Digest. It:

  1. short-circuits if the target is already in effect,
  2. :func:`~pyakuvox.identify.identify` the dialect,
  3. drives the right web client (:class:`WebUIClient` / :class:`WebApiClient`),
  4. **verifies** the result — for Digest modes by proving the digest ``/api``
     answers ``200`` (retrying across candidate password encodings, since the
     FCGI UI is shared by X916 ``base64`` and R29C ``raw`` firmware); for other
     modes by reading the auth mode back.

It never trusts the write alone. :func:`enable_api_digest` is the thin
convenience wrapper for the Digest case. Gentle by design — one login per
attempt, the SPA client backs off on throttle.
"""

from __future__ import annotations

import contextlib
import ssl

import httpx
import structlog
from pydantic import BaseModel

from pyakuvox.clients.local.webapi import WebApiClient
from pyakuvox.clients.local.webui import (
    ConfigPasswordEncoding,
    FirmwareAuthMode,
    HttpApiConfig,
    WebUIClient,
)
from pyakuvox.identify import ApiDialect, dialect_for_model, identify

logger = structlog.get_logger(__name__)

# Auth modes whose success can be proven end-to-end by a client digest call.
_DIGEST_MODES = (FirmwareAuthMode.DIGEST, FirmwareAuthMode.BASIC_DIGEST)


class FlipResult(BaseModel):
    """Outcome of an :func:`enable_api` attempt."""

    host: str
    ok: bool = False
    # already-set | applied | not-verified | unsupported-dialect | unreachable
    verdict: str = ""
    auth_mode: FirmwareAuthMode | None = None
    dialect: ApiDialect = ApiDialect.UNKNOWN
    encoding_used: str = ""        # which password encoding finally verified
    error: str = ""


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    return ctx


async def verify_digest(
    host: str,
    api_user: str,
    api_pass: str,
    *,
    timeout: float = 8.0,
) -> bool:
    """True if ``GET /api/system/info`` answers ``200`` to digest auth.

    Tries HTTPS (S5xx) then HTTP (X916/R29C). This is the ground-truth check
    that the API is actually usable headlessly — not just that a write returned
    ``200``.
    """
    auth = httpx.DigestAuth(api_user, api_pass)
    async with httpx.AsyncClient(verify=_ctx(), timeout=httpx.Timeout(timeout),
                                 follow_redirects=True) as c:
        for scheme in ("https", "http"):
            try:
                r = await c.get(f"{scheme}://{host}/api/system/info", auth=auth)
            except (httpx.HTTPError, ssl.SSLError, OSError):
                continue
            if r.status_code == 200:
                return True
    return False


async def _verify(
    host: str, api_user: str, api_pass: str,
    auth_mode: FirmwareAuthMode, cfg: HttpApiConfig | None,
) -> bool:
    """Did the flip take? Digest modes are proven end-to-end; other modes are
    confirmed by the auth mode read back from the device."""
    if auth_mode in _DIGEST_MODES:
        return await verify_digest(host, api_user, api_pass)
    return cfg is not None and cfg.auth_mode == auth_mode


async def _flip_fcgi(
    host: str, web_user: str, web_pass: str, api_user: str, api_pass: str,
    auth_mode: FirmwareAuthMode, model: str, timeout: int,
) -> str:
    """Flip a ``/fcgi/do`` panel; try each encoding, verifying between. Returns
    the encoding that verified, or "" if none did."""
    # Prefer the model-implied encoding first, but try both (firmware varies).
    order = [ConfigPasswordEncoding.R29C, ConfigPasswordEncoding.X916]
    if dialect_for_model(model) is ApiDialect.FCGI_WEB or (model or "").upper().startswith("X916"):
        order = [ConfigPasswordEncoding.X916, ConfigPasswordEncoding.R29C]
    for enc in order:
        try:
            async with WebUIClient(host, timeout=timeout, password_encoding=enc) as ui:
                await ui.login(web_user, web_pass)
                cfg = await ui.enable_api_access(api_user, api_pass, auth_mode)
        except Exception as exc:
            logger.debug("fcgi_flip_attempt_failed", host=host, encoding=enc.value, error=str(exc))
            continue
        if await _verify(host, api_user, api_pass, auth_mode, cfg):
            return enc.value
    return ""


async def _flip_webapi(
    host: str, web_user: str, web_pass: str, api_user: str, api_pass: str,
    auth_mode: FirmwareAuthMode, model: str, timeout: int,
) -> str:
    """Flip an ``/api/web/*`` SPA panel. Returns "web_api" if it verified."""
    async with WebApiClient(host, timeout=timeout) as web:
        await web.login(web_user, web_pass)
        cfg = await web.enable_api_access(api_user, api_pass, auth_mode)
    return "web_api" if await _verify(host, api_user, api_pass, auth_mode, cfg) else ""


async def enable_api(
    host: str,
    *,
    web_user: str,
    web_pass: str,
    api_user: str,
    api_pass: str,
    auth_mode: FirmwareAuthMode = FirmwareAuthMode.DIGEST,
    model: str | None = None,
    timeout: int = 15,
) -> FlipResult:
    """Set a panel's HTTP-API auth mode with the given API creds, any dialect.

    Idempotent for Digest modes: returns ``already-set`` if the creds already
    work. Dispatches on the identified dialect and verifies the result.
    ``web_user``/``web_pass`` are the web-UI login; ``api_user``/``api_pass`` are
    installed as the API creds. ``auth_mode`` selects the target mode (default
    Digest). ``model`` (optional) biases the FCGI encoding order.
    """
    res = FlipResult(host=host, auth_mode=auth_mode)

    if auth_mode in _DIGEST_MODES and await verify_digest(host, api_user, api_pass):
        res.ok, res.verdict, res.dialect = True, "already-set", ApiDialect.DIGEST_API
        return res

    ident = await identify(host)
    res.dialect = ident.dialect
    model = model or ident.model
    if not ident.reachable:
        res.verdict = "unreachable"
        return res

    if ident.dialect is ApiDialect.WEB_API:
        paths = [_flip_webapi]
    elif ident.dialect is ApiDialect.FCGI_WEB:
        paths = [_flip_fcgi]
    elif ident.dialect is ApiDialect.DIGEST_API:
        # Digest API blocked by WhiteList/None — underlying UI is FCGI or SPA.
        paths = [_flip_fcgi, _flip_webapi]
    else:  # LEGACY_WEB (E18C), UNKNOWN — browser-JS login not yet ported
        res.verdict = "unsupported-dialect"
        return res

    last_err = ""
    for path in paths:
        try:
            used = await path(host, web_user, web_pass, api_user, api_pass,
                              auth_mode, model or "", timeout)
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            logger.debug("flip_path_error", host=host, path=path.__name__, error=last_err)
            continue
        if used:
            res.ok, res.verdict, res.encoding_used = True, "applied", used
            return res

    res.verdict = "not-verified"
    res.error = last_err
    return res


async def enable_api_digest(
    host: str,
    *,
    web_user: str,
    web_pass: str,
    api_user: str,
    api_pass: str,
    model: str | None = None,
    timeout: int = 15,
) -> FlipResult:
    """Convenience wrapper for the common case: :func:`enable_api` with
    ``auth_mode=Digest`` — make a panel headless-manageable by ``LocalClient``.
    """
    return await enable_api(
        host, web_user=web_user, web_pass=web_pass,
        api_user=api_user, api_pass=api_pass,
        auth_mode=FirmwareAuthMode.DIGEST, model=model, timeout=timeout,
    )
