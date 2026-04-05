"""Akuvox web UI encoding utilities.

The Akuvox web UI uses a custom "PostEncode" scheme in its JavaScript
to safely transmit form values. This module replicates that encoding
and the password hashing flow used during login and config changes.

Reverse-engineered from the Akuvox X916 web UI JavaScript
(firmware 916.30.10.114).
"""

from __future__ import annotations

import base64

# PostEncode replacement map — order matters (backtick MUST be first).
_POST_ENCODE_MAP: list[tuple[str, str]] = [
    ("`", "`A"),
    ("&", "`B"),
    ("=", "`C"),
    (" ", "`D"),
    ("\r\n", "`E"),
    ("'", "`F"),
    ("%", "`G"),
    ("/", "`H"),
    ("$", "`I"),
    ("#", "`J"),
    ("+", "`K"),
]


def post_encode(value: str) -> str:
    """Apply Akuvox PostEncode escaping.

    Replaces special characters with backtick-prefixed codes
    so values can be safely embedded in SubmitData form strings.
    """
    for char, replacement in _POST_ENCODE_MAP:
        value = value.replace(char, replacement)
    return value


def encode_login_password(random_string: str, password: str) -> str:
    """Encode a password for the web UI login (CreateSession).

    Flow: Base64(random_string + password) → PostEncode
    The random string comes from GET /fcgi/do?action=Encrypt.
    """
    raw = random_string + password
    b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return post_encode(b64)


def encode_config_password(password: str) -> str:
    """Encode a password for HTTP API config page submission.

    Flow: Base64(password) → PostEncode
    Used when setting the hcPassword field on the config page.
    """
    b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
    return post_encode(b64)
