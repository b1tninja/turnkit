"""STUN wire constants and the raw header and attribute scanner (RFC 8489 sec. 5, sec. 14).

Nothing here interprets an attribute. ``scan`` turns a datagram into
``(type, header_offset, value_length)`` triples and is the single place that decides where
an attribute starts and ends, so that integrity checking and decoding cannot disagree.
"""

from __future__ import annotations

import struct

__all__ = [
    "HEADER_LENGTH",
    "MAGIC_COOKIE",
    "NotStunError",
    "StunFormatError",
    "WrongCookieError",
    "padded",
    "parse_header",
    "scan",
]

MAGIC_COOKIE = 0x2112A442
HEADER_LENGTH = 20


class StunFormatError(ValueError):
    """The bytes are not a well-formed STUN message or attribute."""


class NotStunError(StunFormatError):
    """The top two bits of the first byte are not zero: this is not a STUN message (sec. 5)."""


class WrongCookieError(StunFormatError):
    """The magic cookie is wrong, so this is not an RFC 5389 or RFC 8489 message (sec. 5)."""


def padded(length: int) -> int:
    """Length rounded up to the 32-bit boundary every attribute ends on (sec. 14)."""
    return (length + 3) & ~3


def parse_header(raw: bytes, *, exact: bool = True) -> tuple[int, int, bytes]:
    """Validate the 20-byte header and return ``(message_type, length, transaction_id)``.

    With ``exact`` the length field must equal the octets after the header, which is the
    datagram rule; a stream reader passes ``exact=False`` and checks length itself.
    """
    if len(raw) < HEADER_LENGTH:
        raise StunFormatError("shorter than the 20-byte STUN header")
    message_type, length, cookie = struct.unpack_from(">HHI", raw)
    if message_type & 0xC000:
        raise NotStunError("the two most significant bits must be zero")
    if cookie != MAGIC_COOKIE:
        raise WrongCookieError(f"magic cookie is {cookie:#010x}, not {MAGIC_COOKIE:#010x}")
    if length % 4:
        raise StunFormatError("message length is not a multiple of 4")
    if exact and length != len(raw) - HEADER_LENGTH:
        raise StunFormatError(
            f"length field says {length} octets, the datagram has {len(raw) - HEADER_LENGTH}"
        )
    return message_type, length, bytes(raw[8:HEADER_LENGTH])


def scan(raw: bytes) -> list[tuple[int, int, int]]:
    """Locate every attribute of a datagram: ``(type, header_offset, value_length)``.

    An attribute that runs past the end of the message raises ``StunFormatError``. Padding
    bytes are skipped and not inspected: the receiver MUST ignore them (sec. 14).
    """
    if len(raw) < HEADER_LENGTH:
        raise StunFormatError("shorter than the 20-byte STUN header")
    found: list[tuple[int, int, int]] = []
    end = HEADER_LENGTH + struct.unpack_from(">H", raw, 2)[0]
    if end != len(raw):
        raise StunFormatError("length field does not match the message size")
    pos = HEADER_LENGTH
    while pos < end:
        if pos + 4 > end:
            raise StunFormatError("truncated attribute header")
        attr_type, length = struct.unpack_from(">HH", raw, pos)
        if pos + 4 + padded(length) > end:
            raise StunFormatError(f"attribute {attr_type:#06x} runs past the end of the message")
        found.append((attr_type, pos, length))
        pos += 4 + padded(length)
    return found
