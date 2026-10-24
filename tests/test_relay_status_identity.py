"""Status envelopes and explicit output identity observed on S-series devices."""

import pytest

from pyakuvox.clients.local.parsers import parse_relay_status
from pyakuvox.exceptions import ParseError


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"retcode": 0, "data": {"RelayA": 1}}, [(1, "1")]),
        (
            {"retcode": 0, "data": {"RelayC": 0, "RelayA": 1, "RelayB": 0}},
            [(1, "1"), (2, "0"), (3, "0")],
        ),
        ({"RelayC": 0}, [(3, "0")]),
        ({"relay2": "closed", "relay1": "open"}, [(1, "open"), (2, "closed")]),
        ([{"number": 2, "state": "closed"}], [(2, "closed")]),
        ({"data": [{"number": 3, "state": None}]}, [(3, None)]),
    ],
)
def test_status_preserves_explicit_output_identity(payload, expected):
    assert [(relay.number, relay.state) for relay in parse_relay_status(payload)] == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"data": "invalid"},
        {"RelayZ": 0},
        {"RelayA": 0, "relay1": 0},
        {"RelayA": {"state": 0}},
        [{"number": 0}],
        [{"number": True}],
        [{"number": 1}, {"number": 1}],
        ["invalid"],
    ],
)
def test_invalid_status_cannot_validate_a_selected_output(payload):
    with pytest.raises(ParseError):
        parse_relay_status(payload)
