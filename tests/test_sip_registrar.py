"""Offline tests for the sip_registrar_keys helper (SIP repoint / clear-backup)."""
from pyakuvox.clients.local.client import sip_registrar_keys


def test_keys_for_account_and_server():
    k = sip_registrar_keys(2, "192.0.2.11")
    assert k == {
        "Config.Account2.SIP.Server": "192.0.2.11",
        "Config.Account2.SIP.Server2": "",
    }


def test_backup_included_when_given():
    k = sip_registrar_keys(1, "192.0.2.11", "198.51.100.36")
    assert k["Config.Account1.SIP.Server"] == "192.0.2.11"
    assert k["Config.Account1.SIP.Server2"] == "198.51.100.36"


def test_single_path_clears_backup():
    # tunnel-only: empty Server2 un-strands a panel stuck on a public backup
    k = sip_registrar_keys(2, "192.0.2.11", "")
    assert k["Config.Account2.SIP.Server2"] == ""
