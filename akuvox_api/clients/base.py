"""Base client interface for Akuvox device communication."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from akuvox_api.models.device import DeviceInfo, DeviceStatus, RelayState
from akuvox_api.models.events import CallEvent, DoorEvent, RelayActionResult
from akuvox_api.models.firmware import FirmwareInfo
from akuvox_api.models.schedules import Schedule
from akuvox_api.models.users import UserCode


class AkuvoxClientBase(ABC):
    """Abstract interface for Akuvox device operations.

    Both local and cloud clients implement this so the service
    layer can swap providers transparently.
    """

    @abstractmethod
    async def get_device_info(self) -> DeviceInfo: ...

    @abstractmethod
    async def get_device_status(self) -> DeviceStatus: ...

    @abstractmethod
    async def get_firmware_info(self) -> FirmwareInfo: ...

    @abstractmethod
    async def get_relay_status(self) -> list[RelayState]: ...

    @abstractmethod
    async def trigger_relay(self, relay_num: int, delay: int = 5) -> RelayActionResult: ...

    @abstractmethod
    async def list_users(self, page: int | None = None) -> list[UserCode]: ...

    @abstractmethod
    async def list_schedules(self, page: int | None = None) -> list[Schedule]: ...

    @abstractmethod
    async def get_door_logs(self, page: int | None = None) -> list[DoorEvent]: ...

    @abstractmethod
    async def get_call_logs(self, page: int | None = None) -> list[CallEvent]: ...

    @abstractmethod
    async def get_config(self) -> dict[str, Any]: ...

    @abstractmethod
    async def set_config(self, settings: dict[str, str]) -> None: ...

    async def reboot(self) -> bool:
        """Reboot the device. Override if supported."""
        raise NotImplementedError("Reboot not supported by this client")
