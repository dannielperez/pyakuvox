"""Network migration helpers for Akuvox/Akubela devices.

Akuvox and Akubela firmware families expose network settings through a few
different local surfaces. The stable part is the data model; the exact config
keys or form endpoint should be selected per model/firmware after probing.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class NetworkConfig:
    """Static IPv4 network settings for an Akuvox/Akubela endpoint."""

    old_ip: str
    new_ip: str
    netmask: str
    gateway: str
    dns1: str = "8.8.8.8"
    dns2: str = "1.1.1.1"
    dhcp_enabled: bool = False


@dataclass(frozen=True)
class CustomPostProfile:
    """A model/firmware-specific POST profile."""

    name: str
    url_template: str
    body_template: str
    content_type: str = "application/x-www-form-urlencoded"


@dataclass(frozen=True)
class ConfigKeyMap:
    """Key names for ``LocalClient.set_config`` network updates."""

    dhcp: str
    ip: str
    netmask: str
    gateway: str
    dns1: str
    dns2: str


def map_ip(old_ip: str, old_subnet: str, new_subnet: str) -> str:
    """Map an IP from one subnet to another while preserving host offset."""

    old_net = ipaddress.ip_network(old_subnet, strict=False)
    new_net = ipaddress.ip_network(new_subnet, strict=False)
    old = ipaddress.ip_address(old_ip)
    if old not in old_net:
        raise ValueError(f"{old_ip} is not inside {old_net}")
    host = int(old) - int(old_net.network_address)
    return str(ipaddress.ip_address(int(new_net.network_address) + host))


def plan_static_network(
    old_ip: str,
    old_subnet: str,
    new_subnet: str,
    *,
    gateway: str | None = None,
    dns1: str = "8.8.8.8",
    dns2: str = "1.1.1.1",
) -> NetworkConfig:
    """Build a static network config by preserving the old host octet."""

    new_net = ipaddress.ip_network(new_subnet, strict=False)
    return NetworkConfig(
        old_ip=old_ip,
        new_ip=map_ip(old_ip, old_subnet, new_subnet),
        netmask=str(new_net.netmask),
        gateway=gateway or str(next(new_net.hosts())),
        dns1=dns1,
        dns2=dns2,
    )


def render_url(profile: CustomPostProfile, config: NetworkConfig) -> str:
    """Render a custom POST URL from a profile and config."""

    return profile.url_template.format(**asdict(config))


def render_body(profile: CustomPostProfile, config: NetworkConfig) -> str:
    """Render a custom POST body from a profile and config."""

    return profile.body_template.format(**asdict(config))


def build_config_set_payload(config: NetworkConfig, keys: ConfigKeyMap) -> dict[str, str]:
    """Build a ``LocalClient.set_config`` payload using an explicit key map."""

    return {
        keys.dhcp: "1" if config.dhcp_enabled else "0",
        keys.ip: config.new_ip,
        keys.netmask: config.netmask,
        keys.gateway: config.gateway,
        keys.dns1: config.dns1,
        keys.dns2: config.dns2,
    }
