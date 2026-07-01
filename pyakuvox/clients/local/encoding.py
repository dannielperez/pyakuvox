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
    """Encode an HTTP API config password for the **X916 FCGI** web UI.

    Flow: Base64(password) → PostEncode
    Used when setting the hcPassword field on the X916 ``/fcgi/do`` config page.
    """
    b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
    return post_encode(b64)


def encode_config_password_legacy(password: str) -> str:
    """Encode an HTTP API config password for the **R29/R29C FCGI** web UI.

    Flow: PostEncode(RAW password) — **NOT** base64.

    The R29C firmware stores the field as received (and digest then hashes the
    raw password), so the wire value must be the raw password, PostEncoded only
    for safe form transport. Sending the X916 ``encode_config_password``
    (base64) here makes digest auth return 401 (the firmware would need to, but
    does not, base64-decode it). Verified on R29C panels.
    """
    return post_encode(password)


def encode_config_password_webapi(password: str) -> str:
    """Encode an HTTP API config password for the **S5xx SPA** ``/api/web``.

    Flow: Base64(password) — plain, no PostEncode.

    The Vue SPA's ``St()`` helper is ``base64(utf8(pw))`` over the standard
    alphabet; the JSON transport needs no backtick escaping. The firmware
    base64-decodes it to recover the raw password, so digest auth then works
    with the raw password. Writing the RAW password instead makes the firmware
    base64-decode it into garbage → digest 401. Verified on S535.
    """
    return base64.b64encode(password.encode("utf-8")).decode("ascii")
