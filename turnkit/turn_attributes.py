"""TURN attributes, methods, error codes and ChannelData (RFC 8656 sec. 12.4, 17, 18, 19).

Attribute type numbers are RFC 8656 Table 5; method numbers Table 4. ICMP follows the
reading of erratum 8901 (reported, not verified): ICMP Type and ICMP Code are 8 bits each,
which is also what ICMP and ICMPv6 define; the printed figure's misplaced bar would make
them 7 and 9 bits.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .attributes import (
    FAMILY_IPV4,
    FAMILY_IPV6,
    decode_error_code,
    encode_error_code,
    encode_xor_mapped_address,
    xor_mapped_address,
)
from .message import Attribute
from .wire import StunFormatError, padded

__all__ = [
    "ADDITIONAL_ADDRESS_FAMILY",
    "ADDRESS_ERROR_CODE",
    "ALLOCATE",
    "CHANNEL_BIND",
    "CHANNEL_NUMBER",
    "CREATE_PERMISSION",
    "DATA",
    "DATA_METHOD",
    "DONT_FRAGMENT",
    "EVEN_PORT",
    "ICMP",
    "LIFETIME",
    "REFRESH",
    "REQUESTED_ADDRESS_FAMILY",
    "REQUESTED_TRANSPORT",
    "RESERVATION_TOKEN",
    "SEND",
    "UDP",
    "XOR_PEER_ADDRESS",
    "XOR_RELAYED_ADDRESS",
    "ChannelData",
    "decode_address_error_code",
    "decode_channel_data",
    "decode_channel_number",
    "decode_even_port",
    "decode_icmp",
    "decode_lifetime",
    "decode_requested_address_family",
    "decode_requested_transport",
    "decode_reservation_token",
    "decode_xor_peer_address",
    "decode_xor_relayed_address",
    "encode_additional_address_family",
    "encode_address_error_code",
    "encode_channel_data",
    "encode_channel_number",
    "encode_data",
    "encode_dont_fragment",
    "encode_even_port",
    "encode_icmp",
    "encode_lifetime",
    "encode_requested_address_family",
    "encode_requested_transport",
    "encode_reservation_token",
    "encode_xor_peer_address",
    "encode_xor_relayed_address",
    "stream_channel_data_length",
]

# Methods, Table 4.
ALLOCATE = 0x003
REFRESH = 0x004
SEND = 0x006
DATA_METHOD = 0x007
CREATE_PERMISSION = 0x008
CHANNEL_BIND = 0x009

# Attributes, Table 5.
CHANNEL_NUMBER = 0x000C
LIFETIME = 0x000D
XOR_PEER_ADDRESS = 0x0012
DATA = 0x0013
XOR_RELAYED_ADDRESS = 0x0016
REQUESTED_ADDRESS_FAMILY = 0x0017
EVEN_PORT = 0x0018
REQUESTED_TRANSPORT = 0x0019
DONT_FRAGMENT = 0x001A
RESERVATION_TOKEN = 0x0022
ADDITIONAL_ADDRESS_FAMILY = 0x8000
ADDRESS_ERROR_CODE = 0x8001
ICMP = 0x8004

UDP = 17  # sec. 18.8: the only transport protocol code point this specification allows


def _need(value: bytes, size: int, name: str) -> None:
    if len(value) != size:
        raise StunFormatError(f"{name} value is {size} octets, got {len(value)}")


def encode_xor_peer_address(ip: str, port: int, transaction_id: bytes) -> Attribute:
    """XOR-PEER-ADDRESS (sec. 18.3), encoded as XOR-MAPPED-ADDRESS."""
    return encode_xor_mapped_address(ip, port, transaction_id, XOR_PEER_ADDRESS)


def decode_xor_peer_address(value: bytes, transaction_id: bytes) -> tuple[str, int]:
    """Decode an XOR-PEER-ADDRESS value to ``(ip, port)``."""
    return xor_mapped_address(value, transaction_id)


def encode_xor_relayed_address(ip: str, port: int, transaction_id: bytes) -> Attribute:
    """XOR-RELAYED-ADDRESS (sec. 18.5), encoded as XOR-MAPPED-ADDRESS."""
    return encode_xor_mapped_address(ip, port, transaction_id, XOR_RELAYED_ADDRESS)


def decode_xor_relayed_address(value: bytes, transaction_id: bytes) -> tuple[str, int]:
    """Decode an XOR-RELAYED-ADDRESS value to ``(ip, port)``."""
    return xor_mapped_address(value, transaction_id)


def encode_channel_number(channel: int) -> Attribute:
    """CHANNEL-NUMBER (sec. 18.1); channels 0x4000 to 0x4FFF are free to use (sec. 22)."""
    if not 0x4000 <= channel <= 0x4FFF:
        raise StunFormatError("channel numbers to use are 0x4000 to 0x4FFF (RFC 8656 sec. 22)")
    return Attribute(CHANNEL_NUMBER, struct.pack(">HH", channel, 0))


def decode_channel_number(value: bytes) -> int:
    """Decode CHANNEL-NUMBER; RFFU is ignored. Numbers below 0x4000 conflict with STUN."""
    _need(value, 4, "CHANNEL-NUMBER")
    channel = struct.unpack_from(">H", value)[0]
    if channel < 0x4000:
        raise StunFormatError("channel numbers below 0x4000 conflict with the STUN header")
    return channel


def encode_lifetime(seconds: int) -> Attribute:
    """LIFETIME (sec. 18.2): a 32-bit count of seconds."""
    if not 0 <= seconds <= 0xFFFFFFFF:
        raise StunFormatError("LIFETIME is a 32-bit number of seconds")
    return Attribute(LIFETIME, struct.pack(">I", seconds))


def decode_lifetime(value: bytes) -> int:
    """Decode LIFETIME to seconds."""
    _need(value, 4, "LIFETIME")
    return int(struct.unpack_from(">I", value)[0])


def encode_data(data: bytes) -> Attribute:
    """DATA (sec. 18.4): the application data, padded by the message encoder."""
    return Attribute(DATA, bytes(data))


def encode_requested_transport(protocol: int = UDP) -> Attribute:
    """REQUESTED-TRANSPORT (sec. 18.8); only UDP (17) is allowed when sending."""
    if protocol != UDP:
        raise StunFormatError("RFC 8656 sec. 18.8 only allows code point 17 (UDP)")
    return Attribute(REQUESTED_TRANSPORT, struct.pack(">B3x", protocol))


def decode_requested_transport(value: bytes) -> int:
    """Decode REQUESTED-TRANSPORT to the protocol number; a server answers 442 for non-UDP."""
    _need(value, 4, "REQUESTED-TRANSPORT")
    return int(value[0])


def encode_dont_fragment() -> Attribute:
    """DONT-FRAGMENT (sec. 18.9): no value."""
    return Attribute(DONT_FRAGMENT, b"")


def encode_even_port(reserve_next: bool) -> Attribute:
    """EVEN-PORT (sec. 18.7): one byte, the R flag in the top bit, RFFU zero."""
    return Attribute(EVEN_PORT, bytes([0x80 if reserve_next else 0x00]))


def decode_even_port(value: bytes) -> bool:
    """Decode EVEN-PORT to the R flag; RFFU is ignored."""
    _need(value, 1, "EVEN-PORT")
    return bool(value[0] & 0x80)


def encode_reservation_token(token: bytes) -> Attribute:
    """RESERVATION-TOKEN (sec. 18.10): 8 octets."""
    _need(token, 8, "RESERVATION-TOKEN")
    return Attribute(RESERVATION_TOKEN, bytes(token))


def decode_reservation_token(value: bytes) -> bytes:
    """Decode RESERVATION-TOKEN."""
    _need(value, 8, "RESERVATION-TOKEN")
    return bytes(value)


def encode_requested_address_family(family: int) -> Attribute:
    """REQUESTED-ADDRESS-FAMILY (sec. 18.6): family 0x01 or 0x02, 24 reserved bits."""
    if family not in (FAMILY_IPV4, FAMILY_IPV6):
        raise StunFormatError("address family is 0x01 (IPv4) or 0x02 (IPv6)")
    return Attribute(REQUESTED_ADDRESS_FAMILY, struct.pack(">B3x", family))


def decode_requested_address_family(value: bytes) -> int:
    """Decode REQUESTED-ADDRESS-FAMILY or ADDITIONAL-ADDRESS-FAMILY to the family byte."""
    _need(value, 4, "address family attribute")
    if value[0] not in (FAMILY_IPV4, FAMILY_IPV6):
        raise StunFormatError("address family is 0x01 (IPv4) or 0x02 (IPv6)")
    return int(value[0])


def encode_additional_address_family() -> Attribute:
    """ADDITIONAL-ADDRESS-FAMILY (sec. 18.11); 0x02 is the only valid value in an Allocate."""
    return Attribute(ADDITIONAL_ADDRESS_FAMILY, struct.pack(">B3x", FAMILY_IPV6))


def encode_address_error_code(family: int, code: int, reason: str = "") -> Attribute:
    """ADDRESS-ERROR-CODE (sec. 18.12): family, 13 reserved bits, class, number, reason."""
    if family not in (FAMILY_IPV4, FAMILY_IPV6):
        raise StunFormatError("address family is 0x01 (IPv4) or 0x02 (IPv6)")
    error = encode_error_code(code, reason).value  # same class/number/reason layout
    return Attribute(ADDRESS_ERROR_CODE, bytes([family]) + error[1:])


def decode_address_error_code(value: bytes) -> tuple[int, int, str]:
    """Decode ADDRESS-ERROR-CODE to ``(family, code, reason)`` (440 or 508 per sec. 18.12)."""
    if len(value) < 4:
        raise StunFormatError("ADDRESS-ERROR-CODE shorter than 4 octets")
    family = value[0]
    if family not in (FAMILY_IPV4, FAMILY_IPV6):
        raise StunFormatError("address family is 0x01 (IPv4) or 0x02 (IPv6)")
    code, reason = decode_error_code(b"\x00" + value[1:])
    return family, code, reason


def encode_icmp(icmp_type: int, icmp_code: int, error_data: int = 0) -> Attribute:
    """ICMP (sec. 18.13, erratum 8901 reading): 16 reserved bits, type, code, 32-bit error data."""
    if not (0 <= icmp_type <= 255 and 0 <= icmp_code <= 255 and 0 <= error_data <= 0xFFFFFFFF):
        raise StunFormatError("ICMP type and code are 8 bits, error data is 32 bits")
    return Attribute(ICMP, struct.pack(">HBBI", 0, icmp_type, icmp_code, error_data))


def decode_icmp(value: bytes) -> tuple[int, int, int]:
    """Decode ICMP to ``(type, code, error_data)``; error data is the next-hop MTU for
    ICMPv4 type 3 code 4 and ICMPv6 type 2, otherwise zero (sec. 18.13)."""
    _need(value, 8, "ICMP")
    _, icmp_type, icmp_code, error_data = struct.unpack(">HBBI", value)
    return icmp_type, icmp_code, error_data


@dataclass(frozen=True)
class ChannelData:
    """A ChannelData message (sec. 12.4): a channel number and the application data."""

    channel: int
    data: bytes


def encode_channel_data(channel: int, data: bytes, *, pad: bool = False) -> bytes:
    """Encode ChannelData (sec. 12.4). Padding to a multiple of four is required over TCP and
    TLS-over-TCP and optional over UDP (sec. 12.5); the Length field never counts it."""
    if not 0x4000 <= channel <= 0x4FFF:
        raise StunFormatError("channel numbers to use are 0x4000 to 0x4FFF (RFC 8656 sec. 22)")
    if len(data) > 0xFFFF:
        raise StunFormatError("ChannelData length is 16 bits")
    out = struct.pack(">HH", channel, len(data)) + data
    return out + bytes(padded(len(out)) - len(out)) if pad else out


def stream_channel_data_length(header: bytes) -> int:
    """Total octets of the ChannelData message starting with ``header`` over a stream:
    (4 + Length) rounded up to a multiple of four (sec. 12.5)."""
    if len(header) < 4:
        raise StunFormatError("ChannelData header is 4 octets")
    return 4 + padded(struct.unpack_from(">H", header, 2)[0])


def decode_channel_data(raw: bytes, *, stream: bool = False) -> ChannelData:
    """Decode ChannelData (sec. 12.4, sec. 12.6).

    A channel number in 0x5000 to 0xFFFF is reserved and the message is to be silently
    discarded (here: refused), as is a datagram too short for its claimed length. Over a
    stream the size must be exactly the padded size; over UDP the padding may be absent.
    """
    if len(raw) < 4:
        raise StunFormatError("ChannelData is shorter than its 4-octet header")
    channel, length = struct.unpack_from(">HH", raw)
    if channel < 0x4000:
        raise StunFormatError("not ChannelData: channel number conflicts with the STUN header")
    if channel > 0x4FFF:
        raise StunFormatError("channel number is in the reserved range 0x5000 to 0xFFFF")
    allowed = {4 + padded(length)} if stream else {4 + length, 4 + padded(length)}
    if len(raw) not in allowed:
        raise StunFormatError("datagram size does not match the ChannelData length field")
    return ChannelData(channel, bytes(raw[4 : 4 + length]))
