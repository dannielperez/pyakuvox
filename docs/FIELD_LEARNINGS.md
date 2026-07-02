# pyakuvox — Field Learnings

Hard-won facts from configuring Akuvox intercoms (R29/R29C/X916/S535/R27) across
a multi-device deployment over a VPN. Drove the fixes below; the rest are TODOs.

## Verified API facts
- **Config GET** `GET /api/config/get` returns an **envelope**: the autop key=value
  map is under `["data"]` (`{"retcode":0,"action":"get","message":"OK","data":{…}}`).
- **Config SET** requires the action envelope:
  `POST /api/config/set {"target":"config","action":"set","data":{<key>:<val>}}`.
  Posting the bare dict → `"unsupport action"`. **(fixed in `set_config`)**
- **Reboot**: `POST /api/system/reboot {"target":"system","action":"reboot"}` → retcode 0.
  **(fixed in `reboot`; capability matrix can be promoted from UNVERIFIED→VERIFIED)**
- Most devices serve `/api` on **HTTP :80**; some are **HTTPS-only :443** (HTTP→HTTPS 308).
  Try 80 then 443.
- Old firmware negotiates weak DH / legacy TLS → modern OpenSSL refuses. **`legacy_tls`
  setting added** (permissive SSL ctx: min-version lowered + `SECLEVEL=0`). Needed on some older units.

## Auth model (the "403" trap)
- HTTP-API auth modes: `0=none, 1=basic, 2=whitelist, 4=digest` (see `FirmwareAuthMode`).
- **A 403 with no `WWW-Authenticate` ≠ "API off"** — it's usually **whitelist mode (2) with
  an empty whitelist**, which denies everyone. Confirmed via `WebUIClient.get_http_api_config()`.
- Devices were mixed: some digest(4) (usable), many whitelist(2) (locked out).
- **Fix:** admin web-UI login still works → `WebUIClient.enable_api_access(username, password,
  auth_mode=DIGEST)` flips whitelist→digest. **Set the API account = the account that logs in.**
- Use **HTTP Digest** for `/api` (Basic is broken on some firmware).

## SIP failover config (Account 2)
Keys: `Config.Account2.GENERAL.Enable`/`.Label`, `Config.Account2.SIP.Server`/`.Server2`/
`.Port`/`.Port2`/`.TransType` (0=UDP), **`Config.Account2.REG.Timeout`/`.Timeout2`** (registration
period — was **1800s** by default, the real cause of slow failover; set to **30**).
Dual-server = explicit internal-primary + public-failover. **Reboot after any change** (these
devices can lose unsaved config on power loss).

## TODO / improvements
- **SPA-firmware web-UI client (HIGH):** newer firmware replaced the `/fcgi/do` nonce flow with a
  modern SPA — `WebUIClient.login()` fails with "Failed to get encryption nonce". A meaningful share
  of devices are unreachable for auth-mode flips until this is built (reverse the SPA login + config endpoints).
- Add a `get_config_data()` helper returning the unwrapped `["data"]` map.
- ~~Add a typed `set_sip_account(account_idx, server, server2, ...)` + `set_reg_period()` helper.~~
  **(done: `AkuvoxDevice.set_sip_server` / `set_reg_period` / `set_sip_failover` — the last is the
  one-shot recipe: servers + 30s reg period in one write, verify read, reboot-after-apply)**
- Promote `reboot` capability to VERIFIED.
