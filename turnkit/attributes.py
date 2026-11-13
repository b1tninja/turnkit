"""STUN attribute values (RFC 8489 sec. 14, sec. 18.3): addresses, errors and algorithms.

Each ``encode_*`` returns an :class:`Attribute`; each decoder takes the attribute's value
and raises ``StunFormatError`` on anything the RFC says is malformed. Reserved bits are
written as zero and ignored on receipt, as the sections require.
"""

from __future__ import annotations

import ipaddress
import struct

from .message import Attribute
from .wire import MAGIC_COOKIE, StunFormatError

__all__ = [
    "ALTERNATE_DOMAIN",
    "ALTERNATE_SERVER",
    "ERROR_CODE",
    "FAMILY_IPV4",
    "FAMILY_IPV6",
    "MAPPED_ADDRESS",
    "NONCE",
    "PASSWORD_ALGORITHM",
    "PASSWORD_ALGORITHMS",
    "REALM",
    "SOFTWARE",
    "UNKNOWN_ATTRIBUTES",
    "USERHASH",
    "USERNAME",
    "XOR_MAPPED_ADDRESS",
    "decode_error_code",
    "decode_password_algorithm",
    "decode_password_algorithms",
    "decode_unknown_attributes",
    "encode_error_code",
    "encode_mapped_address",
    "encode_password_algorithm",
    "encode_password_algorithms",
    "encode_text",
    "encode_unknown_attributes",
    "encode_xor_mapped_address",
    "mapped_address",
    "xor_mapped_address",
]

MAPPED_ADDRESS = 0x0001
USERNAME = 0x0006
ERROR_CODE = 0x0009
UNKNOWN_ATTRIBUTES = 0x000A
REALM = 0x0014
NONCE = 0x0015
XOR_MAPPED_ADDRESS = 0x0020
PASSWORD_ALGORITHM = 0x001D
USERHASH = 0x001E
PASSWORD_ALGORITHMS = 0x8002
ALTERNATE_DOMAIN = 0x8003
SOFTWARE = 0x8022
ALTERNATE_SERVER = 0x8023

FAMILY_IPV4 = 0x01
FAMILY_IPV6 = 0x02
_COOKIE = struct.pack(">I", MAGIC_COOKIE)


def _xor(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, mask, strict=False))


def _encode_address(attribute_type: int, ip: str, port: int, mask: bytes | None) -> Attribute:
    if not 0 <= port <= 0xFFFF:
        raise StunFormatError("port is 16 bits")
    address = ipaddress.ip_address(ip)
    family = FAMILY_IPV4 if address.version == 4 else FAMILY_IPV6
    packed = address.packed
    if mask is not None:
        port ^= MAGIC_COOKIE >> 16
        packed = _xor(packed, mask)
    return Attribute(attribute_type, struct.pack(">BBH", 0, family, port) + packed)


def _decode_address(value: bytes, mask: bytes | None) -> tuple[str, int]:
    if len(value) < 4:
        raise StunFormatError("address attribute shorter than 4 octets")
    _, family, port = struct.unpack_from(">BBH", value)
    if family == FAMILY_IPV4:
        size = 4
    elif family == FAMILY_IPV6:
        size = 16
    else:
        raise StunFormatError(f"unknown address family {family:#04x}")
    if len(value) != 4 + size:
        raise StunFormatError("address length does not match its family")
    packed = value[4:]
    if mask is not None:
        port ^= MAGIC_COOKIE >> 16
        packed = _xor(packed, mask)
    return str(ipaddress.ip_address(packed)), port


def encode_mapped_address(ip: str, port: int, attribute_type: int = MAPPED_ADDRESS) -> Attribute:
    """MAPPED-ADDRESS (sec. 14.1); also the form of ALTERNATE-SERVER (sec. 14.15)."""
    return _encode_address(attribute_type, ip, port, None)


def mapped_address(value: bytes) -> tuple[str, int]:
    """Decode a MAPPED-ADDRESS value to ``(ip, port)``."""
    return _decode_address(value, None)


def encode_xor_mapped_address(
    ip: str, port: int, transaction_id: bytes, attribute_type: int = XOR_MAPPED_ADDRESS
) -> Attribute:
    """XOR-MAPPED-ADDRESS (sec. 14.2): port XOR the cookie's high 16 bits; the address XOR
    the cookie (IPv4) or the cookie and transaction ID (IPv6)."""
    if len(transaction_id) != 12:
        raise StunFormatError("transaction ID is 96 bits")
    return _encode_address(attribute_type, ip, port, _COOKIE + transaction_id)


def xor_mapped_address(value: bytes, transaction_id: bytes) -> tuple[str, int]:
    """Decode an XOR-MAPPED-ADDRESS value (sec. 14.2) to ``(ip, port)``."""
    if len(transaction_id) != 12:
        raise StunFormatError("transaction ID is 96 bits")
    return _decode_address(value, _COOKIE + transaction_id)


def encode_text(attribute_type: int, text: str, *, limit: int = 509) -> Attribute:
    """A UTF-8 text attribute (USERNAME, REALM, NONCE, SOFTWARE; sec. 14.3, 14.9, 14.10, 14.14).

    The RFC allows fewer than 128 characters, up to 509 octets when encoding. Preparation
    with OpaqueString (RFC 8265) is the caller's job; see ``turnkit.credentials``.
    """
    raw = text.encode("utf-8")
    if len(raw) > limit or len(text) >= 128:
        raise StunFormatError("text attribute is limited to fewer than 128 characters, 509 octets")
    return Attribute(attribute_type, raw)


def encode_error_code(code: int, reason: str = "") -> Attribute:
    """ERROR-CODE (sec. 14.8): class 3 to 6, number 0 to 99, UTF-8 reason phrase."""
    if not 300 <= code <= 699:
        raise StunFormatError("ERROR-CODE is 300 to 699")
    raw = reason.encode("utf-8")
    if len(raw) > 509 or len(reason) >= 128:
        raise StunFormatError("reason phrase is limited to fewer than 128 characters")
    return Attribute(ERROR_CODE, struct.pack(">HBB", 0, code // 100, code % 100) + raw)


def decode_error_code(value: bytes) -> tuple[int, str]:
    """Decode ERROR-CODE to ``(code, reason)``. Reserved bits are ignored (sec. 14.8)."""
    if len(value) < 4:
        raise StunFormatError("ERROR-CODE shorter than 4 octets")
    klass = value[2] & 0x07
    number = value[3]
    if not 3 <= klass <= 6 or number > 99:
        raise StunFormatError("ERROR-CODE class must be 3 to 6 and number 0 to 99")
    try:
        reason = value[4:].decode("utf-8")
    except UnicodeDecodeError as error:
        raise StunFormatError("ERROR-CODE reason phrase is not UTF-8") from error
    return klass * 100 + number, reason


def encode_unknown_attributes(types: list[int]) -> Attribute:
    """UNKNOWN-ATTRIBUTES (sec. 14.13): 16-bit types, normal padding (not the RFC 3489 duplication)."""
    if not all(0 <= t <= 0xFFFF for t in types):
        raise StunFormatError("attribute types are 16 bits")
    return Attribute(UNKNOWN_ATTRIBUTES, b"".join(struct.pack(">H", t) for t in types))


def decode_unknown_attributes(value: bytes) -> list[int]:
    """Decode UNKNOWN-ATTRIBUTES to the list of types."""
    if len(value) % 2:
        raise StunFormatError("UNKNOWN-ATTRIBUTES is a list of 16-bit values")
    return [struct.unpack_from(">H", value, i)[0] for i in range(0, len(value), 2)]


def encode_password_algorithm(algorithm: int, parameters: bytes = b"") -> Attribute:
    """PASSWORD-ALGORITHM (sec. 14.12): algorithm, parameter length, parameters."""
    return Attribute(
        PASSWORD_ALGORITHM, struct.pack(">HH", algorithm, len(parameters)) + parameters
    )


def _padding(length: int) -> int:
    return (-length) % 4


def decode_password_algorithm(value: bytes) -> tuple[int, bytes]:
    """Decode PASSWORD-ALGORITHM to ``(algorithm, parameters)``."""
    if len(value) < 4:
        raise StunFormatError("PASSWORD-ALGORITHM shorter than 4 octets")
    algorithm, length = struct.unpack_from(">HH", value)
    if len(value) < 4 + length:
        raise StunFormatError("PASSWORD-ALGORITHM parameters are truncated")
    return algorithm, value[4 : 4 + length]


def encode_password_algorithms(algorithms: list[tuple[int, bytes]]) -> Attribute:
    """PASSWORD-ALGORITHMS (sec. 14.11): each entry's parameters padded to 32 bits."""
    out = b""
    for algorithm, parameters in algorithms:
        out += struct.pack(">HH", algorithm, len(parameters)) + parameters
        out += bytes(_padding(len(parameters)))
    return Attribute(PASSWORD_ALGORITHMS, out)


def decode_password_algorithms(value: bytes) -> list[tuple[int, bytes]]:
    """Decode PASSWORD-ALGORITHMS to a list of ``(algorithm, parameters)``."""
    found: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(value):
        if pos + 4 > len(value):
            raise StunFormatError("PASSWORD-ALGORITHMS entry header is truncated")
        algorithm, length = struct.unpack_from(">HH", value, pos)
        end = pos + 4 + length
        if end + _padding(length) > len(value):
            raise StunFormatError("PASSWORD-ALGORITHMS entry is truncated")
        found.append((algorithm, value[pos + 4 : end]))
        pos = end + _padding(length)
    return found
