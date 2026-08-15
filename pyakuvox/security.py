"""Secret-free security evidence returned by the high-level device facade."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Collection

    from pyakuvox.models.users import UserCode


class CredentialRisk(StrEnum):
    """Risk classification for an authenticated management credential."""

    ACCEPTABLE = "acceptable"
    VENDOR_DEFAULT = "vendor_default"
    KNOWN_WEAK = "known_weak"


@dataclass(frozen=True)
class UserAccountSummary:
    """Persistable user metadata with PIN and card values deliberately omitted."""

    stable_key: str
    name: str
    user_id: str
    has_pin: bool
    has_card: bool
    schedule_relay: str
    web_relay: str
    lift_floor_num: str
    user_type: str
    source: str
    source_type: str
    is_cloud_provisioned: bool


@dataclass(frozen=True)
class SecuritySnapshot:
    """Authenticated credential assessment plus a complete local user catalog."""

    credential_risk: CredentialRisk
    users: tuple[UserAccountSummary, ...]


_VENDOR_DEFAULT_CREDENTIALS = frozenset({("admin", "admin")})


def assess_credential(
    username: str,
    password: str,
    *,
    weak_passwords: Collection[str] = (),
    treat_username_as_weak: bool = False,
) -> CredentialRisk:
    """Classify an Akuvox credential using caller-supplied generic policy.

    Akuvox's shipped ``admin``/``admin`` credential is always recognized as a
    vendor default. Generic weak-password dictionaries and username matching
    default off so applications can inject their own cross-vendor policy.
    """
    normalized_username = username.strip().casefold()
    if (normalized_username, password) in _VENDOR_DEFAULT_CREDENTIALS:
        return CredentialRisk.VENDOR_DEFAULT
    normalized_password = password.casefold()
    normalized_weak_passwords = {value.casefold() for value in weak_passwords}
    if normalized_password in normalized_weak_passwords or (
        treat_username_as_weak
        and normalized_username
        and normalized_password == normalized_username
    ):
        return CredentialRisk.KNOWN_WEAK
    return CredentialRisk.ACCEPTABLE


def summarize_user(user: UserCode) -> UserAccountSummary:
    """Normalize one device user using a stable, device-scoped identity key."""
    if user.id:
        stable_key = f"id:{user.id}"
    elif user.user_id:
        stable_key = f"user:{user.user_id}"
    else:
        # Some firmware can omit both identifiers. Hash only non-secret,
        # persisted metadata so anonymous rows remain distinct and stable
        # without incorporating PIN or card values into the identity.
        identity_material = "\0".join(
            (
                user.name,
                user.schedule_relay,
                user.web_relay or "",
                user.lift_floor_num or "",
                user.user_type or "",
                user.source or "",
                user.source_type or "",
                str(user.is_cloud_provisioned),
            ),
        )
        stable_key = f"anonymous:{sha256(identity_material.encode()).hexdigest()[:32]}"
    return UserAccountSummary(
        stable_key=stable_key,
        name=user.name,
        user_id=user.user_id,
        has_pin=user.has_pin,
        has_card=user.has_card,
        schedule_relay=user.schedule_relay,
        web_relay=user.web_relay or "",
        lift_floor_num=user.lift_floor_num or "",
        user_type=user.user_type or "",
        source=user.source or "",
        source_type=user.source_type or "",
        is_cloud_provisioned=user.is_cloud_provisioned,
    )
