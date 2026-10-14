# Optional X916 building display setting

A live UniqueOS retry on Murano X916 firmware916.30.10.114 failed on missing Config.DoorSetting.GENERAL.BuildingDisplayType after optional name visibility support passed. Add caller-controlled building_display_required (default true). Opting out skips only that absent display field; present fields still apply, required dialing/DTMF/relay fields retain strict validation and readback. UniqueOS residential preset opts out. No live SDK mutation here.

Validation: 13 intercom configuration tests passed; changed-file Ruff/format passed. Unknown asyncio_mode warning is from the shared test environment. Default behavior remains strict for other callers.
