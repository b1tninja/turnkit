"""MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 and FINGERPRINT (RFC 8489 sec. 14.5 to 14.7).

All three cover the header's length field, so the field is rewritten before hashing to end
where the attribute being computed ends (sec. 14.5 para 3 and 4, sec. 14.7 para 5): the classic
STUN bug is hashing with the final length instead. Comparisons use ``hmac.compare_digest``.

Rules applied when checking a received message:

* only the first MESSAGE-INTEGRITY (and first MESSAGE-INTEGRITY-SHA256) counts; duplicates
  may be ignored (sec. 14 para 5);
* attributes after MESSAGE-INTEGRITY are not covered, except MESSAGE-INTEGRITY-SHA256 and
  FINGERPRINT (sec. 9 para 3);
* FINGERPRINT must be the last attribute (sec. 14.7 para 3), so a FINGERPRINT that is not
  last fails ``check_fingerprint``.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from typing import Literal

from .wire import HEADER_LENGTH, StunFormatError, scan

__all__ = [
    "FINGERPRINT",
    "MESSAGE_INTEGRITY",
    "MESSAGE_INTEGRITY_SHA256",
    "check_fingerprint",
    "check_message_integrity",
    "fingerprint_value",
    "message_integrity_value",
]

MESSAGE_INTEGRITY = 0x0008
MESSAGE_INTEGRITY_SHA256 = 0x001C
FINGERPRINT = 0x8028
_FINGERPRINT_XOR = 0x5354554E

Algorithm = Literal["sha1", "sha256"]


def _with_length(prefix: bytes, total: int) -> bytes:
    """``prefix`` (header plus attributes so far) with the length field set for ``total``."""
    return prefix[:2] + struct.pack(">H", total - HEADER_LENGTH) + prefix[4:]


def message_integrity_value(
    prefix: bytes, key: bytes, algorithm: Algorithm = "sha1", length: int | None = None
) -> bytes:
    """HMAC for a MESSAGE-INTEGRITY(-SHA256) attribute that will follow ``prefix``.

    ``prefix`` is the message up to but excluding the attribute. SHA-1 gives 20 octets;
    SHA-256 gives ``length`` octets (default 32; 16 to 32, a multiple of 4, sec. 14.6).
    """
    if algorithm == "sha1":
        size, digest = 20, hashlib.sha1
        if length not in (None, 20):
            raise ValueError("MESSAGE-INTEGRITY is exactly 20 octets")
    else:
        size, digest = (32 if length is None else length), hashlib.sha256
        if not 16 <= size <= 32 or size % 4:
            raise ValueError("MESSAGE-INTEGRITY-SHA256 is 16 to 32 octets, a multiple of 4")
    adjusted = _with_length(prefix, len(prefix) + 4 + size)
    return hmac.new(key, adjusted, digest).digest()[:size]


def fingerprint_value(prefix: bytes) -> bytes:
    """The 4-octet FINGERPRINT value for an attribute that will follow ``prefix``."""
    adjusted = _with_length(prefix, len(prefix) + 8)
    return struct.pack(">I", (zlib.crc32(adjusted) ^ _FINGERPRINT_XOR) & 0xFFFFFFFF)


def check_fingerprint(data: bytes) -> bool:
    """True if a FINGERPRINT is present, is the last attribute and has the right value."""
    try:
        attributes = scan(data)
    except StunFormatError:
        return False
    if not attributes or attributes[-1][0] != FINGERPRINT or attributes[-1][2] != 4:
        return False
    offset = attributes[-1][1]
    return hmac.compare_digest(data[offset + 4 : offset + 8], fingerprint_value(data[:offset]))


def check_message_integrity(data: bytes, key: bytes, algorithm: Algorithm = "sha1") -> bool:
    """True if the first MESSAGE-INTEGRITY(-SHA256) of ``data`` matches ``key``.

    False when the attribute is absent, malformed or wrong; the caller decides what a
    missing attribute means for its usage (sec. 9.1.3, sec. 9.2.4).
    """
    wanted = MESSAGE_INTEGRITY if algorithm == "sha1" else MESSAGE_INTEGRITY_SHA256
    try:
        attributes = scan(data)
    except StunFormatError:
        return False
    for attr_type, offset, length in attributes:
        if attr_type != wanted:
            continue
        if algorithm == "sha1" and length != 20:
            return False
        if algorithm == "sha256" and not (16 <= length <= 32 and length % 4 == 0):
            return False
        expected = message_integrity_value(data[:offset], key, algorithm, length)
        return hmac.compare_digest(data[offset + 4 : offset + 4 + length], expected)
    return False
