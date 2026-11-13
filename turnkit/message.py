"""STUN message and attribute codec (RFC 8489 sec. 5, sec. 14).

Decisions, each pinned by a test:

* ``decode_message`` validates the header and attribute framing and returns every attribute
  raw, in order, including ones it does not know and including MESSAGE-INTEGRITY and
  FINGERPRINT. It does not verify integrity: that needs a key, see ``turnkit.integrity``.
* The length field must equal the octets after the header (a datagram). A stream reader
  uses ``stream_message_length`` on the first 20 octets instead.
* Padding bytes are not stored and are written as zero (sec. 14 para 4: zero on sending,
  ignored on receipt). The RFC 5769 vectors pad with spaces, so they re-encode to different
  bytes: check integrity against the received bytes, never against a re-encoding.
* An attribute with type below 0x8000 that this library does not know is reported by
  ``Attribute.comprehension_required``; deciding what to do is the usage's job (sec. 14 para 6).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Literal

from .integrity import (
    FINGERPRINT,
    MESSAGE_INTEGRITY,
    MESSAGE_INTEGRITY_SHA256,
    fingerprint_value,
    message_integrity_value,
)
from .wire import (
    HEADER_LENGTH,
    MAGIC_COOKIE,
    NotStunError,
    StunFormatError,
    WrongCookieError,
    padded,
    parse_header,
    scan,
)

__all__ = [
    "BINDING",
    "HEADER_LENGTH",
    "MAGIC_COOKIE",
    "Attribute",
    "Message",
    "NotStunError",
    "StunClass",
    "StunFormatError",
    "WrongCookieError",
    "decode_message",
    "encode_message",
    "looks_like_stun",
    "make_message_type",
    "split_message_type",
    "stream_message_length",
]

BINDING = 0x001


class StunClass(IntEnum):
    """The two class bits of the message type (RFC 8489 sec. 5)."""

    REQUEST = 0b00
    INDICATION = 0b01
    SUCCESS = 0b10
    ERROR = 0b11


def make_message_type(method: int, klass: int) -> int:
    """Interleave a 12-bit method and a 2-bit class into the 14-bit type (sec. 5, Figure 3)."""
    if not 0 <= method <= 0xFFF or not 0 <= klass <= 3:
        raise ValueError("method is 12 bits and class is 2 bits")
    return (
        ((method & 0xF80) << 2)
        | ((klass & 2) << 7)
        | ((method & 0x70) << 1)
        | ((klass & 1) << 4)
        | (method & 0xF)
    )


def split_message_type(message_type: int) -> tuple[int, StunClass]:
    """Inverse of :func:`make_message_type`: ``(method, class)``."""
    method = ((message_type & 0x3E00) >> 2) | ((message_type & 0xE0) >> 1) | (message_type & 0xF)
    klass = ((message_type & 0x100) >> 7) | ((message_type & 0x10) >> 4)
    return method, StunClass(klass)


@dataclass(frozen=True)
class Attribute:
    """One attribute: its type and its value without padding."""

    type: int
    value: bytes = b""

    @property
    def comprehension_required(self) -> bool:
        """Types 0x0000 to 0x7FFF must be understood to process the message (sec. 14)."""
        return self.type < 0x8000


@dataclass(frozen=True)
class Message:
    """A STUN message: the 14-bit type, the 96-bit transaction ID and the attributes in order."""

    message_type: int
    transaction_id: bytes
    attributes: tuple[Attribute, ...] = ()

    @property
    def method(self) -> int:
        return split_message_type(self.message_type)[0]

    @property
    def klass(self) -> StunClass:
        return split_message_type(self.message_type)[1]

    def find(self, attribute_type: int) -> Attribute | None:
        """The first attribute of a type; only the first needs processing (sec. 14 para 5)."""
        for attribute in self.attributes:
            if attribute.type == attribute_type:
                return attribute
        return None


def looks_like_stun(data: bytes) -> bool:
    """Cheap demultiplexing test: top bits zero, magic cookie, length a multiple of 4.

    Meant for telling STUN from DTLS, RTP and ChannelData on one port (sec. 5 para 5, 13, 15).
    It does not validate the attributes.
    """
    if len(data) < HEADER_LENGTH:
        return False
    message_type, length, cookie = struct.unpack_from(">HHI", data)
    return not message_type & 0xC000 and cookie == MAGIC_COOKIE and length % 4 == 0


def stream_message_length(header: bytes) -> int:
    """Total octets of the message whose first 20 octets are ``header`` (for a TCP reader)."""
    _, length, _ = parse_header(header[:HEADER_LENGTH], exact=False)
    return HEADER_LENGTH + length


def decode_message(raw: bytes) -> Message:
    """Decode one datagram (RFC 8489 sec. 5, sec. 14); integrity is not verified here."""
    message_type, _, transaction_id = parse_header(raw)
    attributes = tuple(
        Attribute(attr_type, bytes(raw[offset + 4 : offset + 4 + length]))
        for attr_type, offset, length in scan(raw)
    )
    return Message(message_type, transaction_id, attributes)


def _serialise(attribute: Attribute) -> bytes:
    if not 0 <= attribute.type <= 0xFFFF:
        raise StunFormatError("attribute type is 16 bits")
    if len(attribute.value) > 0xFFFF:
        raise StunFormatError("attribute value is longer than 65535 octets")
    pad = padded(len(attribute.value)) - len(attribute.value)
    return struct.pack(">HH", attribute.type, len(attribute.value)) + attribute.value + bytes(pad)


def encode_message(
    msg: Message,
    key: bytes | None = None,
    *,
    integrity: Literal["sha1", "sha256"] = "sha1",
    fingerprint: bool = False,
) -> bytes:
    """Encode a message (RFC 8489 sec. 5, sec. 14), optionally signing it.

    With ``key`` a MESSAGE-INTEGRITY (``integrity="sha1"``) or MESSAGE-INTEGRITY-SHA256
    attribute is appended; with ``fingerprint`` a FINGERPRINT follows, always last. The
    message must not already carry those attributes.
    """
    if msg.message_type & 0xC000 or msg.message_type < 0:
        raise StunFormatError("message type is 14 bits")
    if len(msg.transaction_id) != 12:
        raise StunFormatError("transaction ID is 96 bits")
    owned = {MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256, FINGERPRINT}
    if (key is not None or fingerprint) and any(a.type in owned for a in msg.attributes):
        raise StunFormatError("the message already has an integrity or fingerprint attribute")
    body = b"".join(_serialise(attribute) for attribute in msg.attributes)

    def header(length: int) -> bytes:
        if length > 0xFFFF:
            raise StunFormatError("message is longer than 65535 octets after the header")
        return struct.pack(">HHI", msg.message_type, length, MAGIC_COOKIE) + msg.transaction_id

    out = header(len(body)) + body
    if key is not None:
        if integrity == "sha1":
            attribute = Attribute(MESSAGE_INTEGRITY, message_integrity_value(out, key))
        else:
            attribute = Attribute(
                MESSAGE_INTEGRITY_SHA256, message_integrity_value(out, key, "sha256")
            )
        out += _serialise(attribute)
        out = header(len(out) - HEADER_LENGTH) + out[HEADER_LENGTH:]
    if fingerprint:
        out += _serialise(Attribute(FINGERPRINT, fingerprint_value(out)))
        out = header(len(out) - HEADER_LENGTH) + out[HEADER_LENGTH:]
    return out
