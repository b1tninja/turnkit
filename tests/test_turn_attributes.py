"""TURN attributes, ChannelData and the STUN attribute helpers (RFC 8656 sec. 12.4, 17-19)."""

from __future__ import annotations

import struct

import pytest

from turnkit import attributes as a
from turnkit import turn_attributes as t
from turnkit.message import Message, decode_message, encode_message, make_message_type
from turnkit.wire import StunFormatError

TID = bytes(range(12))


def test_attribute_type_numbers_are_table_5():
    assert (t.CHANNEL_NUMBER, t.LIFETIME, t.XOR_PEER_ADDRESS, t.DATA) == (0x0C, 0x0D, 0x12, 0x13)
    assert (t.XOR_RELAYED_ADDRESS, t.REQUESTED_ADDRESS_FAMILY, t.EVEN_PORT) == (0x16, 0x17, 0x18)
    assert (t.REQUESTED_TRANSPORT, t.DONT_FRAGMENT, t.RESERVATION_TOKEN) == (0x19, 0x1A, 0x22)
    assert (t.ADDITIONAL_ADDRESS_FAMILY, t.ADDRESS_ERROR_CODE, t.ICMP) == (0x8000, 0x8001, 0x8004)
    # Table 4: methods
    assert (t.ALLOCATE, t.REFRESH, t.SEND, t.DATA_METHOD) == (3, 4, 6, 7)
    assert (t.CREATE_PERMISSION, t.CHANNEL_BIND) == (8, 9)


def test_allocate_request_roundtrip_with_turn_attributes():
    request = Message(
        make_message_type(t.ALLOCATE, 0),
        TID,
        (
            t.encode_requested_transport(),
            t.encode_lifetime(600),
            t.encode_even_port(True),
            t.encode_dont_fragment(),
            t.encode_requested_address_family(a.FAMILY_IPV6),
        ),
    )
    raw = encode_message(request)
    assert raw[:2] == b"\x00\x03"  # Allocate request
    decoded = decode_message(raw)
    values = {x.type: x.value for x in decoded.attributes}
    assert t.decode_requested_transport(values[t.REQUESTED_TRANSPORT]) == 17
    assert t.decode_lifetime(values[t.LIFETIME]) == 600
    assert t.decode_even_port(values[t.EVEN_PORT]) is True
    assert values[t.DONT_FRAGMENT] == b""
    assert t.decode_requested_address_family(values[t.REQUESTED_ADDRESS_FAMILY]) == 2
    # EVEN-PORT is one octet padded to four; DONT-FRAGMENT has no value
    assert values[t.EVEN_PORT] == b"\x80"
    assert len(raw) == 20 + 8 + 8 + 8 + 4 + 8


def test_requested_transport_only_udp_when_sending():
    assert t.encode_requested_transport().value == b"\x11\x00\x00\x00"
    with pytest.raises(StunFormatError, match="17"):
        t.encode_requested_transport(6)
    assert t.decode_requested_transport(b"\x06\x00\x00\x00") == 6  # a server answers 442


def test_reserved_bits_are_zero_on_send_and_ignored_on_receipt():
    assert t.encode_channel_number(0x4000).value == b"\x40\x00\x00\x00"
    assert t.decode_channel_number(b"\x40\x01\xff\xff") == 0x4001
    assert t.decode_even_port(b"\x7f") is False
    assert t.decode_requested_address_family(b"\x01\xff\xff\xff") == 1


def test_channel_number_range():
    for bad in (0x3FFF, 0x5000, 0xFFFF):
        with pytest.raises(StunFormatError):
            t.encode_channel_number(bad)
    assert t.decode_channel_number(struct.pack(">HH", 0x4FFF, 0)) == 0x4FFF
    with pytest.raises(StunFormatError, match="STUN header"):
        t.decode_channel_number(struct.pack(">HH", 0x3FFF, 0))


def test_lifetime_and_token_sizes():
    assert t.encode_lifetime(0xFFFFFFFF).value == b"\xff\xff\xff\xff"
    with pytest.raises(StunFormatError):
        t.encode_lifetime(2**32)
    with pytest.raises(StunFormatError):
        t.decode_lifetime(b"\x00\x00\x00")
    token = bytes(range(8))
    assert t.decode_reservation_token(t.encode_reservation_token(token).value) == token
    with pytest.raises(StunFormatError):
        t.encode_reservation_token(bytes(7))


def test_peer_and_relayed_addresses_use_xor_mapped_encoding():
    peer = t.encode_xor_peer_address("2001:db8::1", 4000, TID)
    relayed = t.encode_xor_relayed_address("192.0.2.15", 49152, TID)
    assert peer.type == t.XOR_PEER_ADDRESS and relayed.type == t.XOR_RELAYED_ADDRESS
    assert t.decode_xor_peer_address(peer.value, TID) == ("2001:db8::1", 4000)
    assert t.decode_xor_relayed_address(relayed.value, TID) == ("192.0.2.15", 49152)
    assert peer.value[2:4] == struct.pack(">H", 4000 ^ 0x2112)


def test_address_family_attributes():
    assert t.encode_additional_address_family().value == b"\x02\x00\x00\x00"
    with pytest.raises(StunFormatError):
        t.encode_requested_address_family(3)
    with pytest.raises(StunFormatError):
        t.decode_requested_address_family(b"\x03\x00\x00\x00")


def test_address_error_code_layout():
    attribute = t.encode_address_error_code(a.FAMILY_IPV6, 440, "Address Family not Supported")
    assert attribute.value[:4] == bytes(
        [2, 0, 4, 40]
    )  # family, 13 reserved bits, class 4, number 40
    assert t.decode_address_error_code(attribute.value) == (2, 440, "Address Family not Supported")
    insufficient = t.encode_address_error_code(a.FAMILY_IPV4, 508)
    assert insufficient.value[:4] == bytes([1, 0, 5, 8])
    with pytest.raises(StunFormatError):
        t.encode_address_error_code(9, 440)
    with pytest.raises(StunFormatError):
        t.decode_address_error_code(bytes([2, 0, 2, 40]))  # class 2 is not an error class


def test_icmp_fields_are_8_bits_each_per_erratum_8901():
    attribute = t.encode_icmp(3, 4, 1400)  # ICMPv4 destination unreachable, fragmentation needed
    assert attribute.value == bytes.fromhex("0000 0304 00000578".replace(" ", ""))
    assert t.decode_icmp(attribute.value) == (3, 4, 1400)
    assert t.decode_icmp(t.encode_icmp(255, 255).value) == (255, 255, 0)
    with pytest.raises(StunFormatError):
        t.encode_icmp(256, 0)


def test_error_code_attribute():
    attribute = a.encode_error_code(437, "Allocation Mismatch")
    assert attribute.value[:4] == bytes([0, 0, 4, 37])
    assert a.decode_error_code(attribute.value) == (437, "Allocation Mismatch")
    for bad in (299, 700):
        with pytest.raises(StunFormatError):
            a.encode_error_code(bad)
    with pytest.raises(StunFormatError):
        a.decode_error_code(bytes([0, 0, 2, 0]))
    with pytest.raises(StunFormatError):
        a.decode_error_code(bytes([0, 0, 4, 100]))
    # the reserved bits above the class are ignored on receipt
    assert a.decode_error_code(bytes([0xFF, 0xFF, 0xFC, 41]))[0] == 441


def test_unknown_attributes_and_password_algorithms():
    unknown = a.encode_unknown_attributes([0x0777, 0x0778, 0x0779])
    assert a.decode_unknown_attributes(unknown.value) == [0x0777, 0x0778, 0x0779]
    algorithms = [(1, b""), (2, b""), (0x8001, b"abc")]
    encoded = a.encode_password_algorithms(algorithms)
    assert len(encoded.value) % 4 == 0
    assert a.decode_password_algorithms(encoded.value) == algorithms
    assert a.decode_password_algorithm(a.encode_password_algorithm(2).value) == (2, b"")
    with pytest.raises(StunFormatError):
        a.decode_password_algorithms(encoded.value[:-2])


def test_text_attribute_limits():
    assert a.encode_text(a.SOFTWARE, "x" * 127).value == b"x" * 127
    with pytest.raises(StunFormatError):
        a.encode_text(a.SOFTWARE, "x" * 128)


def test_mapped_address_rejects_bad_families_and_lengths():
    assert a.mapped_address(a.encode_mapped_address("10.0.0.1", 80).value) == ("10.0.0.1", 80)
    with pytest.raises(StunFormatError):
        a.mapped_address(bytes([0, 3, 0, 80, 1, 2, 3, 4]))
    with pytest.raises(StunFormatError):
        a.mapped_address(bytes([0, 1, 0, 80, 1, 2, 3]))
    with pytest.raises(StunFormatError):
        a.xor_mapped_address(bytes(8), bytes(11))


def test_channel_data_udp_and_stream_padding():
    # sec. 12.4 format; sec. 12.5: padded over TCP, optional over UDP, Length excludes padding
    raw = t.encode_channel_data(0x4001, b"hello")
    assert raw == b"\x40\x01\x00\x05hello"
    assert t.decode_channel_data(raw) == t.ChannelData(0x4001, b"hello")
    padded = t.encode_channel_data(0x4001, b"hello", pad=True)
    assert padded == raw + b"\x00\x00\x00"
    assert t.decode_channel_data(padded) == t.ChannelData(0x4001, b"hello")  # UDP may carry padding
    assert t.decode_channel_data(padded, stream=True).data == b"hello"
    assert t.stream_channel_data_length(padded[:4]) == 12
    with pytest.raises(StunFormatError):
        t.decode_channel_data(raw, stream=True)  # unpadded over a stream
    assert (
        t.decode_channel_data(t.encode_channel_data(0x4000, b"")).data == b""
    )  # length 0 is valid


def test_channel_data_discards():
    with pytest.raises(StunFormatError, match="reserved"):
        t.decode_channel_data(b"\x50\x00\x00\x00")  # 0x5000 and above are reserved
    with pytest.raises(StunFormatError, match="STUN header"):
        t.decode_channel_data(b"\x00\x01\x00\x00")
    with pytest.raises(StunFormatError, match="does not match"):
        t.decode_channel_data(b"\x40\x00\x00\x10abc")  # too short for the claimed length
    with pytest.raises(StunFormatError):
        t.decode_channel_data(b"\x40\x00\x00")
    with pytest.raises(StunFormatError):
        t.decode_channel_data(b"\x40\x00\x00\x01a\x00\x00\x00\x00")  # trailing surplus
