"""STUN credential keys: short-term, long-term and USERHASH (RFC 8489 sec. 9.1.1, 9.2.2, 14.4).

String preparation is the open part. RFC 8489 requires usernames, realms and passwords to
be processed with the OpaqueString profile of RFC 8265 before use. That profile needs
Unicode normalisation and PRECIS tables this library does not carry, so ``opaque_string``
accepts ASCII text (printable characters and space, which OpaqueString leaves unchanged)
and raises ``NotImplementedError`` for anything else. A caller with non-ASCII credentials
must prepare them first and pass the prepared form; the RFC 5769 sec. 2.4 and RFC 8489
appendix B.1 vectors do exactly that (their password is written both before and after
processing, and the key is derived from the processed "TheMatrIX").

Not here: the TURN "REST API" scheme (timestamped username, HMAC password). RFC 7635 does
not define it (it defines OAuth 2.0 access tokens for STUN, sec. 4), no RFC does, and the
roadmap records that as a non-goal until a document can be cited.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "MD5",
    "SHA256",
    "long_term_key",
    "opaque_string",
    "short_term_key",
    "userhash",
]

MD5 = 0x0001  # RFC 8489 sec. 18.5 password algorithm numbers
SHA256 = 0x0002


def opaque_string(text: str) -> str:
    """OpaqueString (RFC 8265) for ASCII input; other input is not implemented.

    ASCII graphic characters and the space are unchanged by the profile. Control characters
    are refused. Anything outside ASCII raises ``NotImplementedError`` rather than guess.
    """
    if not text.isascii():
        raise NotImplementedError(
            "OpaqueString (RFC 8265) for non-ASCII text is not implemented: pass prepared text"
        )
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise ValueError("control characters are not allowed in an OpaqueString")
    return text


def _kept(text: str) -> str:
    return text


def short_term_key(password: str) -> bytes:
    """HMAC key for short-term credentials: ``OpaqueString(password)`` in UTF-8 (sec. 9.1.1)."""
    return opaque_string(password).encode("utf-8")


def long_term_key(
    username: str, realm: str, password: str, algorithm: int = MD5, *, prepared: bool = False
) -> bytes:
    """HMAC key for long-term credentials (RFC 8489 sec. 9.2.2, sec. 18.5.1).

    ``MD5(username ":" OpaqueString(realm) ":" OpaqueString(password))`` is 16 octets;
    SHA-256 is 32. The username is used as it appears in the USERNAME attribute, which has
    already been prepared. MD5 is for compatibility with legacy systems only (sec. 18.5.1.1).
    ``prepared=True`` says realm and password were already processed with OpaqueString.
    """
    if algorithm == MD5:
        digest = hashlib.md5
    elif algorithm == SHA256:
        digest = hashlib.sha256
    else:
        raise ValueError(f"unknown password algorithm {algorithm:#06x}")
    prep = _kept if prepared else opaque_string
    material = f"{username}:{prep(realm)}:{prep(password)}"
    return digest(material.encode("utf-8")).digest()


def userhash(username: str, realm: str, *, prepared: bool = False) -> bytes:
    """USERHASH value: ``SHA-256(OpaqueString(username) ":" OpaqueString(realm))`` (sec. 14.4)."""
    prep = _kept if prepared else opaque_string
    material = f"{prep(username)}:{prep(realm)}"
    return hashlib.sha256(material.encode("utf-8")).digest()
