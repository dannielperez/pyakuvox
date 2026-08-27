import asyncio

from pyakuvox.device import AkuvoxDevice
from pyakuvox.models.users import UserCode
from pyakuvox.security import CredentialRisk, assess_credential, summarize_user


class _UserClient:
    async def list_all_users(self):
        return [
            UserCode(
                id="7",
                name="Operator",
                user_id="operator-7",
                private_pin="1234",
                card_code="sensitive-card",
                source="local",
            ),
        ]


def test_assess_credential_keeps_generic_policy_caller_owned():
    assert assess_credential("admin", "admin") is CredentialRisk.VENDOR_DEFAULT
    assert assess_credential("operator", "123456") is CredentialRisk.ACCEPTABLE
    assert (
        assess_credential("operator", "123456", weak_passwords={"123456"})
        is CredentialRisk.KNOWN_WEAK
    )
    assert (
        assess_credential("operator", "operator", treat_username_as_weak=True)
        is CredentialRisk.KNOWN_WEAK
    )
    assert assess_credential("operator", "long-random-value") is CredentialRisk.ACCEPTABLE


def test_summarize_user_falls_back_to_secret_free_stable_hash():
    first = summarize_user(UserCode(name="First", user_id=""))
    second = summarize_user(UserCode(name="Second", user_id=""))

    assert first.stable_key.startswith("anonymous:")
    assert second.stable_key.startswith("anonymous:")
    assert first.stable_key != second.stable_key


def test_security_snapshot_omits_pin_card_and_password_values():
    snapshot = asyncio.run(
        AkuvoxDevice.from_client(_UserClient()).security_snapshot(
            "operator",
            "long-random-value",
        ),
    )

    assert snapshot.credential_risk is CredentialRisk.ACCEPTABLE
    assert snapshot.users[0].stable_key == "id:7"
    assert snapshot.users[0].has_pin is True
    assert snapshot.users[0].has_card is True
    rendered = repr(snapshot)
    assert "1234" not in rendered
    assert "sensitive-card" not in rendered
    assert "long-random-value" not in rendered
