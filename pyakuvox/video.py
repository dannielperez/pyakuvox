"""Video configuration plans and their guarded, verified application.

Mappings are limited to firmware with observed configuration surfaces. Planning
never mutates a device. ``apply_video_plan`` writes only a reviewed plan, and
only for model/firmware pairs whose write, readback, persistence and restart
behavior were validated on hardware (``_WRITE_VALIDATED``, empty until then).
Recovery material contains only the exact non-secret fields in a proposed patch.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from pyakuvox.exceptions import (
    AkuvoxError,
    AmbiguousMutationError,
    ApiAccessForbiddenError,
    AuthenticationError,
)
from pyakuvox.exceptions import (
    ConnectionError as DeviceConnectionError,
)
from pyakuvox.exceptions import (
    TimeoutError as DeviceTimeoutError,
)
from pyakuvox.sip_recovery import _call_state, _mac

if TYPE_CHECKING:
    from collections.abc import Mapping


class Outcome(StrEnum):
    OBSERVED = "observed"
    UNSUPPORTED = "unsupported"
    FORBIDDEN = "forbidden"
    AUTHENTICATION_FAILED = "authentication-failed"
    UNREACHABLE = "unreachable"
    ERROR = "error"


class Truth(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Codec(Record):
    name: str
    enabled: Truth
    priority: int | None = None
    payload: int | None = None
    packetization_mode: str | None = None


class VideoObservation(Record):
    outcome: Outcome
    model: str = ""
    firmware: str = ""
    mac: str = ""
    account: int = 2
    identity: str = ""
    registrar: str = ""
    codecs: tuple[Codec, ...] = ()
    two_way: Truth = Truth.UNKNOWN
    webcall: Truth = Truth.UNKNOWN
    # No raw config, passwords, auth names, URLs, or vendor exception messages.
    values: tuple[tuple[str, str], ...] = ()
    protected_fingerprint: str = ""
    write_supported: bool = False
    reason: str = ""


class VideoIntent(Record):
    h264: bool | None = None
    h263: bool | None = None
    two_way: bool | None = None
    h264_priority: int | None = Field(default=None, ge=0, le=255)
    h263_priority: int | None = Field(default=None, ge=0, le=255)


class Change(Record):
    key: str
    before: str
    after: str


class VideoPlan(Record):
    changes: tuple[Change, ...] = ()
    blockers: tuple[str, ...] = ()
    baseline: VideoObservation
    recovery_ready: bool = False
    restart_required: str = "unknown"
    application_supported: bool = False


class Drift(Record):
    state: str  # compliant, drifted, unknown
    fields: tuple[str, ...] = ()


_SURFACES = {("S535", "535.30.10.282"): ("H264",), ("S539", "539.30.10.523"): ("H264", "H263")}
_TWO_WAY = "Config.Features.TWOWAYVIDEO.Enable"
# (model, firmware) pairs whose config write, readback, reboot persistence and
# restart need were validated on a non-production panel. Adding one is a
# reviewed change carrying that evidence; nothing is validated yet.
_WRITE_VALIDATED: frozenset[tuple[str, str]] = frozenset()
_IDENTITY_FIELDS = (
    "model",
    "firmware",
    "mac",
    "account",
    "identity",
    "registrar",
    "protected_fingerprint",
)


def _truth(value: object) -> Truth:
    return {"1": Truth.ENABLED, "0": Truth.DISABLED}.get(str(value), Truth.UNKNOWN)


def _number(value: object) -> int | None:
    return int(str(value)) if str(value).isdigit() else None


def _fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def inspect_video_configuration(
    config: Mapping[str, Any],
    *,
    model: str,
    firmware: str,
    mac: str,
    account: int = 2,
) -> VideoObservation:
    """Normalize a configuration already read by the consumer's authenticated SDK client."""
    if type(account) is not int or not 1 <= account <= 16:
        raise ValueError("account must be between 1 and 16")
    model = model.upper()
    supported = _SURFACES.get((model, firmware))
    if not supported:
        return VideoObservation(
            outcome=Outcome.UNSUPPORTED,
            model=model,
            firmware=firmware,
            mac=mac,
            account=account,
            reason="Unvalidated model/firmware",
        )
    prefix = f"Config.Account{account}."
    values = {}
    codecs = []
    for slot, expected in enumerate(supported):
        key = f"{prefix}Video{slot:02d}."
        if config.get(key + "Name") != expected:
            return VideoObservation(
                outcome=Outcome.UNSUPPORTED,
                model=model,
                firmware=firmware,
                mac=mac,
                account=account,
                reason="Codec surface mismatch",
            )
        for suffix in ("Enable", "Priority"):
            raw = config.get(key + suffix)
            if isinstance(raw, (str, int)) and len(str(raw)) <= 3:
                values[key + suffix] = str(raw)
        codecs.append(
            Codec(
                name=expected,
                enabled=_truth(config.get(key + "Enable")),
                priority=_number(config.get(key + "Priority")),
                payload=_number(config.get(key + "Payload")),
                packetization_mode=str(config.get(key + "PacketizationMode", "")),
            )
        )
    if config.get(_TWO_WAY) in ("0", "1", ""):
        values[_TWO_WAY] = config[_TWO_WAY]
    # Detect unrelated drift without retaining unrelated settings or secrets.
    protected = {
        k: v
        for k, v in config.items()
        if k not in values
        and any(
            s in k
            for s in (
                ".GENERAL.UserName",
                ".SIP.Server",
                ".SIP.Port",
                ".SIP.TransType",
                ".GENERAL.Enable",
                ".DISPLAY.",
                ".RELAY.",
                ".DTMF.",
                ".CALLTIMEOUT.",
            )
        )
    }
    return VideoObservation(
        outcome=Outcome.OBSERVED,
        model=model,
        firmware=firmware,
        mac=mac,
        account=account,
        identity=str(config.get(prefix + "GENERAL.UserName", "")),
        registrar=str(config.get(prefix + "SIP.Server", "")),
        codecs=tuple(codecs),
        two_way=_truth(config.get(_TWO_WAY)),
        values=tuple(sorted(values.items())),
        protected_fingerprint=_fingerprint(protected),
    )


def plan_video_configuration(observed: VideoObservation, intent: VideoIntent) -> VideoPlan:
    """Propose only known fields; an unknown baseline cannot be restored safely."""
    blockers = []
    changes = []
    if observed.outcome is not Outcome.OBSERVED:
        return VideoPlan(baseline=observed, blockers=(observed.outcome.value,))
    values = dict(observed.values)
    names = _SURFACES.get((observed.model, observed.firmware), ())
    for name, enabled, priority in (
        ("H264", intent.h264, intent.h264_priority),
        ("H263", intent.h263, intent.h263_priority),
    ):
        if enabled is None and priority is None:
            continue
        if name not in names:
            blockers.append(f"{name}: unsupported")
            continue
        prefix = f"Config.Account{observed.account}.Video{names.index(name):02d}."
        for suffix, desired in (
            ("Enable", None if enabled is None else str(int(enabled))),
            ("Priority", None if priority is None else str(priority)),
        ):
            if desired is None:
                continue
            key = prefix + suffix
            before = values.get(key)
            valid = (
                before in ("0", "1")
                if suffix == "Enable"
                else (before is not None and before.isdigit() and 0 <= int(before) <= 255)
            )
            if not valid:
                blockers.append(f"{name}.{suffix}: unknown baseline")
            elif before != desired:
                changes.append(Change(key=key, before=str(before), after=desired))
    if intent.two_way is not None:
        before = values.get(_TWO_WAY)
        if before not in ("0", "1"):
            blockers.append("two-way: unknown baseline")
        elif before != str(int(intent.two_way)):
            changes.append(Change(key=_TWO_WAY, before=before, after=str(int(intent.two_way))))
    return VideoPlan(
        baseline=observed,
        changes=tuple(changes),
        blockers=tuple(blockers),
        recovery_ready=not blockers
        and bool(observed.mac and observed.identity and observed.registrar),
        application_supported=(observed.model, observed.firmware) in _WRITE_VALIDATED,
    )


def compare_video_configuration(observed: VideoObservation, intent: VideoIntent) -> Drift:
    plan = plan_video_configuration(observed, intent)
    if plan.blockers:
        return Drift(state="unknown")
    return Drift(
        state="drifted" if plan.changes else "compliant", fields=tuple(c.key for c in plan.changes)
    )


def plan_video_rollback(plan: VideoPlan, current: VideoObservation) -> VideoPlan:
    """Refuse stale identity, unrelated drift or intervening field edits.

    This is recovery *planning*, never a device write. Persistence and hardware
    restoration still require separate approved validation.
    """
    before = plan.baseline
    if not plan.recovery_ready or current.outcome is not Outcome.OBSERVED:
        return VideoPlan(baseline=current, blockers=("Recovery baseline unavailable",))
    if any(getattr(before, key) != getattr(current, key) for key in _IDENTITY_FIELDS):
        return VideoPlan(
            baseline=current, blockers=("Identity or protected configuration changed",)
        )
    values = dict(current.values)
    if any(values.get(c.key) not in (c.before, c.after) for c in plan.changes):
        return VideoPlan(baseline=current, blockers=("Intervening configuration change",))
    return VideoPlan(
        baseline=current,
        recovery_ready=True,
        application_supported=plan.application_supported,
        changes=tuple(
            Change(key=c.key, before=c.after, after=c.before)
            for c in plan.changes
            if values.get(c.key) == c.after
        ),
    )


class VideoReader(Protocol):
    async def get_device_info(self) -> Any: ...
    async def get_config(self) -> dict[str, Any]: ...


async def read_video_configuration(
    client: VideoReader, *, account: int = 2, timeout: float = 10
) -> VideoObservation:
    """Bounded read/readback with safe outcomes; never guess credentials or enable APIs."""
    if not 0 < timeout <= 30:
        raise ValueError("timeout must be between 0 and 30 seconds")
    try:
        async with asyncio.timeout(timeout):
            info = await client.get_device_info()
            raw = await client.get_config()
            return inspect_video_configuration(
                raw.get("data", raw),
                model=info.identity.model,
                firmware=info.firmware_version,
                mac=info.identity.normalized_mac(),
                account=account,
            )
    except ApiAccessForbiddenError:
        outcome = Outcome.FORBIDDEN
    except AuthenticationError:
        outcome = Outcome.AUTHENTICATION_FAILED
    except (TimeoutError, DeviceTimeoutError, DeviceConnectionError, OSError):
        outcome = Outcome.UNREACHABLE
    except (AkuvoxError, ValueError, TypeError, AttributeError):
        outcome = Outcome.ERROR
    return VideoObservation(outcome=outcome, account=account)


class VideoWriter(VideoReader, Protocol):
    async def set_config(self, settings: dict[str, str]) -> None: ...
    async def _get(self, path: str) -> Any: ...


class VideoApplyResult(Record):
    verdict: str  # no-change, set-verified, verification-failed
    applied: bool = False
    verified: bool = False
    changes: tuple[Change, ...] = ()
    observed: tuple[tuple[str, str], ...] = ()
    restart_required: str = "unknown"


def _refuse(reason: str) -> ValueError:
    return ValueError(f"Video change refused: {reason}; no change sent")


async def apply_video_plan(
    client: VideoWriter, plan: VideoPlan, *, expected_mac: str, timeout: float = 30
) -> VideoApplyResult:
    """Write one reviewed plan's exact changes once, then verify by readback.

    Applies a forward plan or a ``plan_video_rollback`` result alike. Refuses,
    sending nothing, unless the pair is hardware-validated, the client does not
    retry, the panel is idle, and a fresh read still matches the plan's identity,
    protected settings and every ``before`` value. Never reboots and never
    restores on its own: after a failed verification, read again, then plan and
    apply a rollback. Once the write starts, an unknown outcome raises
    ``AmbiguousMutationError``. A concurrent change between the final read and
    the write remains possible; this is not a device-side compare-and-swap.
    An external controller must serialize this with other device mutations.
    """
    if not 0 < timeout <= 60:
        raise ValueError("timeout must be between 0 and 60 seconds")
    base = plan.baseline
    if (base.model, base.firmware) not in _WRITE_VALIDATED:
        raise _refuse("write contract not validated on hardware for this model/firmware")
    if getattr(client, "_max_retries", None) != 0:
        raise _refuse("a non-retrying client is required")
    if plan.blockers or not plan.recovery_ready:
        raise _refuse("the plan has blockers or no recovery baseline")
    if len(_mac(expected_mac)) != 12 or _mac(expected_mac) != _mac(base.mac):
        raise _refuse("device identity is not the approved device")
    names = _SURFACES.get((base.model, base.firmware), ())
    allowed = {
        f"Config.Account{base.account}.Video{slot:02d}.{suffix}"
        for slot in range(len(names))
        for suffix in ("Enable", "Priority")
    } | {_TWO_WAY}
    if any(c.key not in allowed for c in plan.changes):
        raise _refuse("the plan touches a field outside the video surface")
    if not plan.changes:
        return VideoApplyResult(verdict="no-change", verified=True, observed=base.values)
    write_started = False
    try:
        async with asyncio.timeout(timeout):
            if _call_state(await client._get("/api/call/status")) != "READY":
                raise _refuse("panel call state is active or unknown")
            current = await read_video_configuration(client, account=base.account)
            if current.outcome is not Outcome.OBSERVED or any(
                getattr(base, key) != getattr(current, key) for key in _IDENTITY_FIELDS
            ):
                raise _refuse("identity or protected configuration changed")
            now = dict(current.values)
            if any(now.get(c.key) != c.before for c in plan.changes):
                raise _refuse("a planned field changed since the plan; review a fresh plan")
            write_started = True
            await client.set_config({c.key: c.after for c in plan.changes})
            after = await read_video_configuration(client, account=base.account)
    except Exception as exc:
        if write_started:
            raise AmbiguousMutationError(
                "Video change outcome unknown; read current configuration before retrying"
            ) from exc
        raise
    expected = {**now, **{c.key: c.after for c in plan.changes}}
    verified = (
        after.outcome is Outcome.OBSERVED
        and all(getattr(base, key) == getattr(after, key) for key in _IDENTITY_FIELDS)
        and dict(after.values) == expected
    )
    return VideoApplyResult(
        verdict="set-verified" if verified else "verification-failed",
        applied=True,
        verified=verified,
        changes=plan.changes,
        observed=after.values,
    )
