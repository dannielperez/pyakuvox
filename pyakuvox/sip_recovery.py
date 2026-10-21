"""Bounded local SIP evidence and idle-only UDP flow renewal.

No credential, registrar or transport changes. Mutating clients MUST disable retries.
"""

import asyncio
import time


def _data(value):
    return value.get("data", value) if isinstance(value, dict) else {}


def _mac(value):
    return "".join(c for c in str(value).lower() if c in "0123456789abcdef")


def _registered(status, slot):
    """Absent, malformed and unfamiliar status values are not registration failures."""
    account = status.get(f"Account{slot}") if isinstance(status, dict) else None
    raw = account.get("Status") if isinstance(account, dict) else None
    if type(raw) not in (str, int):
        return None
    code = str(raw)
    if code == "2":
        return True
    if code in {"0", "1", "3", "-1"}:
        return False
    return None


def _renewal_port(accounts, account):
    if account["transport"] != "UDP":
        raise ValueError("Port renewal supports UDP only; TCP/TLS requires a different recovery")
    if (
        account["local_port_min"] != account["local_port_max"]
        or not account["local_port_min"].isdigit()
    ):
        raise ValueError("A fixed local UDP port is required")
    used = set()
    for a in accounts:
        if not a["enabled"]:
            continue
        if not a["local_port_min"].isdigit() or not a["local_port_max"].isdigit():
            raise ValueError("An enabled account has unknown local ports")
        low, high = int(a["local_port_min"]), int(a["local_port_max"])
        if not 1 <= low <= high <= 65535:
            raise ValueError("An enabled account has an invalid local port range")
        used.update(range(max(5060, low), min(5099, high) + 1))
    used.add(int(account["local_port_min"]))
    port = next((p for p in range(5060, 5100) if p not in used), None)
    if port is None:
        raise ValueError("No free SIP port in the bounded recovery range")
    return port


async def inspect_sip(client):
    """Return an allowlisted report; never return the configuration/password map."""
    config = _data(await client.get_config())
    info = await client.get_device_info()
    status = _data(await client._get("/api/system/info"))
    call = _data(await client._get("/api/call/status"))
    accounts = []
    for slot in range(1, 17):
        prefix = f"Config.Account{slot}."
        if prefix + "GENERAL.Enable" not in config:
            continue
        accounts.append(
            {
                "slot": slot,
                "enabled": config[prefix + "GENERAL.Enable"] == "1",
                "username": str(config.get(prefix + "GENERAL.UserName", ""))[:128],
                "server": str(config.get(prefix + "SIP.Server", ""))[:255],
                "server_port": str(config.get(prefix + "SIP.Port", ""))[:5],
                "transport": {"0": "UDP", "1": "TCP", "2": "TLS"}.get(
                    str(config.get(prefix + "SIP.TransType")), "unknown"
                ),
                "local_port_min": str(config.get(prefix + "SIP.ListenPortMin", ""))[:5],
                "local_port_max": str(config.get(prefix + "SIP.ListenPortMax", ""))[:5],
                "registered": _registered(status, slot),
            }
        )
    for account in accounts:
        try:
            if not account["enabled"]:
                raise ValueError("SIP account is disabled")
            _renewal_port(accounts, account)
        except ValueError as error:
            account["udp_recovery_supported"] = False
            account["udp_recovery_reason"] = str(error)
        else:
            account["udp_recovery_supported"] = True
            account["udp_recovery_reason"] = "UDP port renewal configuration is supported"
    return {
        "mac": info.identity.normalized_mac(),
        "call_state": str(call.get("Status", "UNKNOWN"))[:30],
        "accounts": accounts,
    }


async def renew_udp_flow(client, *, slot, username, server, mac):
    """Sample all-panel idle for 60s, rotate one fixed UDP port, verify or restore.

    Calls must use max_retries=0. Failure/ambiguous writes are never retried.
    An external controller must serialize this with other device mutations.
    """
    if getattr(client, "_max_retries", None) != 0:
        raise ValueError("Flow renewal requires a non-retrying client")
    async with asyncio.timeout(130):
        baseline = await inspect_sip(client)
        rows = [a for a in baseline["accounts"] if a["slot"] == slot]
        if len(_mac(mac)) != 12 or _mac(baseline["mac"]) != _mac(mac) or len(rows) != 1:
            raise ValueError("Device or account identity is not verified")
        account = rows[0]
        if not account["enabled"] or account["username"] != username or account["server"] != server:
            raise ValueError("SIP account differs from the approved target")
        port = _renewal_port(baseline["accounts"], account)
        started = time.monotonic()
        while True:
            if _data(await client._get("/api/call/status")).get("Status") != "READY":
                raise ValueError("Panel call state is active or unknown; no change sent")
            if time.monotonic() - started >= 60:
                break
            await asyncio.sleep(5)
        current = await inspect_sip(client)
        if current != baseline or current["call_state"] != "READY":
            raise ValueError("Panel state changed during preflight; inspect again")
        prefix = f"Config.Account{slot}.SIP."
        before = {
            prefix + "ListenPortMin": account["local_port_min"],
            prefix + "ListenPortMax": account["local_port_max"],
        }
        after = dict.fromkeys(before, str(port))
        result = {
            "before_port": account["local_port_min"],
            "after_port": str(port),
            "slot": slot,
            "verified": False,
            "rollback": "not_needed",
        }
        try:
            await client.set_config(after)
            good = 0
            for _ in range(6):
                await asyncio.sleep(3)
                report = await inspect_sip(client)
                row = next(a for a in report["accounts"] if a["slot"] == slot)
                matched = (
                    _mac(report["mac"]) == _mac(mac)
                    and row["username"] == username
                    and row["server"] == server
                    and row["local_port_min"] == str(port)
                    and row["local_port_max"] == str(port)
                )
                good = good + 1 if matched and row["registered"] else 0
                if good >= 2:
                    result["verified"] = True
                    return result
        except Exception:
            # Response content may contain credentials; retain no exception text.
            result["error"] = "write_or_verification_uncertain"
        finally:
            if not result["verified"]:
                # Read before restore: do not overwrite a concurrent administrator change.
                try:
                    report = await inspect_sip(client)
                    row = next((a for a in report["accounts"] if a["slot"] == slot), {})
                    owned = (
                        _mac(report["mac"]) == _mac(mac)
                        and row.get("username") == username
                        and row.get("server") == server
                        and row.get("transport") == "UDP"
                        and row.get("enabled")
                        and row.get("local_port_min") == str(port)
                        and row.get("local_port_max") == str(port)
                        and report["call_state"] == "READY"
                    )
                    if owned:
                        await client.set_config(before)
                        check = _data(await client.get_config())
                        result["rollback"] = (
                            "verified"
                            if all(check.get(k) == v for k, v in before.items())
                            else "unconfirmed"
                        )
                    else:
                        result["rollback"] = "not_owned_or_busy_or_unknown"
                except Exception:
                    result["rollback"] = "unconfirmed"
        return result
