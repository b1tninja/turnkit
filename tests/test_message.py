"""STUN message codec against RFC 5769 section 2 and the RFC 8489 header rules."""

from __future__ import annotations

import ipaddress
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.vectors import (
    LONG_TERM_REQUEST,
    SAMPLE_IPV4_RESPONSE,
    SAMPLE_IPV6_RESPONSE,
    SAMPLE_REQUEST,
    TRANSACTION_ID,
)
from turnkit import attributes as attrs
from turnkit.message import (
    BINDING,
    Attribute,
    Message,
    NotStunError,
    StunClass,
    StunFormatError,
    WrongCookieError,
    decode_message,
    encode_message,
    looks_like_stun,
    make_message_type,
    split_message_type,
    stream_message_length,
)


def reencode(message: Message) -> bytes:
    return encode_message(message)


def test_rfc5769_sample_request():
    message = decode_message(SAMPLE_REQUEST)
    assert message.message_type == 0x0001
    assert message.method == BINDING and message.klass == StunClass.REQUEST
    assert message.transaction_id == TRANSACTION_ID
    assert [a.type for a in message.attributes] == [0x8022, 0x0024, 0x8029, 0x0006, 0x0008, 0x8028]
    values = {a.type: a.value for a in message.attributes}
    assert values[0x8022] == b"STUN test client"
    assert values[0x0024] == bytes.fromhex("6e0001ff")  # type pref 110, local pref 1, component 1
    assert values[0x0006] == b"evtj:h6vY"  # 9 octets: the 3 padding bytes are not part of it
    assert values[0x0008] == bytes.fromhex("9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2")
    assert values[0x8028] == bytes.fromhex("e57a3bcf")
    # The vector pads with spaces; ours pads with zero, so the encodings differ in exactly
    # those three bytes and are otherwise identical.
    again = reencode(message)
    assert len(again) == len(SAMPLE_REQUEST)
    differing = [i for i, (a, b) in enumerate(zip(again, SAMPLE_REQUEST, strict=True)) if a != b]
    assert len(differing) == 3 and again[differing[0] - 1 : differing[0]] == b"Y"


def test_rfc5769_ipv4_response():
    message = decode_message(SAMPLE_IPV4_RESPONSE)
    assert message.message_type == 0x0101 and message.klass == StunClass.SUCCESS
    mapped = message.find(attrs.XOR_MAPPED_ADDRESS)
    assert mapped is not None
    assert attrs.xor_mapped_address(mapped.value, message.transaction_id) == ("192.0.2.1", 32853)
    software = message.find(attrs.SOFTWARE)
    assert software is not None and software.value == b"test vector"
    # 2.2 is padded with a space as well, so compare against the vector with that byte zeroed
    expected = bytearray(SAMPLE_IPV4_RESPONSE)
    expected[20 + 4 + 11] = 0
    assert reencode(message) == bytes(expected)


def test_ipv6_xor_mapped_address_roundtrip():
    message = decode_message(SAMPLE_IPV6_RESPONSE)
    mapped = message.find(attrs.XOR_MAPPED_ADDRESS)
    assert mapped is not None
    ip, port = attrs.xor_mapped_address(mapped.value, message.transaction_id)
    assert ipaddress.ip_address(ip) == ipaddress.ip_address("2001:db8:1234:5678:11:2233:4455:6677")
    assert port == 32853
    again = attrs.encode_xor_mapped_address(ip, port, message.transaction_id)
    assert again.value == mapped.value  # the cookie AND the transaction ID are in the mask


def test_ipv4_xor_uses_only_the_cookie():
    attribute = attrs.encode_xor_mapped_address("192.0.2.1", 32853, bytes(12))
    assert attribute.value == bytes.fromhex("0001a147e112a643")
    assert attrs.encode_xor_mapped_address("192.0.2.1", 32853, TRANSACTION_ID).value == (
        bytes.fromhex("0001a147e112a643")
    )


def test_long_term_request_decodes_and_reencodes_exactly():
    message = decode_message(LONG_TERM_REQUEST)  # padded with NUL, as encode writes it
    assert [a.type for a in message.attributes] == [0x0006, 0x0015, 0x0014, 0x0008]
    assert message.find(attrs.USERNAME).value.decode() == "マトリックス"
    assert reencode(message) == LONG_TERM_REQUEST


def test_type_bit_interleave():
    assert make_message_type(BINDING, StunClass.REQUEST) == 0x0001
    assert make_message_type(BINDING, StunClass.SUCCESS) == 0x0101
    assert make_message_type(BINDING, StunClass.INDICATION) == 0x0011
    assert make_message_type(BINDING, StunClass.ERROR) == 0x0111
    for method in (0x001, 0x003, 0x0FF, 0x0FFF):
        for klass in StunClass:
            encoded = make_message_type(method, klass)
            assert encoded & 0xC000 == 0
            assert split_message_type(encoded) == (method, klass)
    with pytest.raises(ValueError, match="12 bits"):
        make_message_type(0x1000, 0)


def test_top_two_bits_nonzero_refused():
    for first in (0x40, 0x80, 0xC0):
        raw = bytes([first]) + SAMPLE_REQUEST[1:]
        with pytest.raises(NotStunError):
            decode_message(raw)


def test_wrong_cookie_refused_with_its_own_error():
    raw = SAMPLE_REQUEST[:4] + b"\x00\x00\x00\x00" + SAMPLE_REQUEST[8:]
    with pytest.raises(WrongCookieError):
        decode_message(raw)
    assert issubclass(WrongCookieError, StunFormatError)


def test_length_not_multiple_of_four_refused():
    raw = bytearray(SAMPLE_REQUEST)
    raw[3] = 0x57
    with pytest.raises(StunFormatError, match="multiple of 4"):
        decode_message(bytes(raw))


def test_length_mismatch_refused():
    with pytest.raises(StunFormatError, match="length field"):
        decode_message(SAMPLE_REQUEST[:-4])  # header says 88, buffer holds 84
    with pytest.raises(StunFormatError, match="length field"):
        decode_message(SAMPLE_REQUEST + bytes(4))  # and 92


def test_attribute_overruns_message():
    # one attribute claiming 8 octets in a message that holds only 4 after its header
    raw = struct.pack(">HHI", 1, 8, 0x2112A442) + TRANSACTION_ID + struct.pack(">HH", 0x8022, 8)
    raw += bytes(4)
    with pytest.raises(StunFormatError, match="runs past"):
        decode_message(raw)


def test_attribute_padding_not_in_length():
    message = Message(1, TRANSACTION_ID, (Attribute(0x0006, b"evtj:h6vY"),))
    raw = encode_message(message)
    assert len(raw) == 20 + 4 + 12 and raw[2:4] == b"\x00\x10"
    assert raw[-3:] == b"\x00\x00\x00"
    assert decode_message(raw).attributes[0].value == b"evtj:h6vY"


def test_unknown_comprehension_required_attribute_is_reported_not_dropped():
    message = Message(1, TRANSACTION_ID, (Attribute(0x0777, b"x"), Attribute(0x8777, b"y")))
    decoded = decode_message(encode_message(message))
    assert [(a.type, a.comprehension_required) for a in decoded.attributes] == [
        (0x0777, True),
        (0x8777, False),
    ]


def test_looks_like_stun_demux():
    assert looks_like_stun(SAMPLE_REQUEST)
    assert not looks_like_stun(bytes([22, 254, 253]) + bytes(60))  # a DTLS 1.2 handshake record
    assert not looks_like_stun(bytes([0x80, 0x60]) + bytes(20))  # RTP
    assert not looks_like_stun(bytes([0x40, 0x00, 0x00, 0x04]) + bytes(20))  # ChannelData
    assert not looks_like_stun(SAMPLE_REQUEST[:19])


def test_stream_message_length_from_the_header_alone():
    assert stream_message_length(SAMPLE_REQUEST[:20]) == len(SAMPLE_REQUEST)
    with pytest.raises(StunFormatError):
        stream_message_length(SAMPLE_REQUEST[:10])


def test_truncated_everywhere():
    for cut in range(len(SAMPLE_REQUEST)):
        with pytest.raises(StunFormatError):
            decode_message(SAMPLE_REQUEST[:cut])


def test_encode_refuses_bad_input():
    with pytest.raises(StunFormatError):
        encode_message(Message(1, bytes(11)))
    with pytest.raises(StunFormatError):
        encode_message(Message(0x4000, bytes(12)))
    with pytest.raises(StunFormatError):
        encode_message(Message(1, bytes(12), (Attribute(0x8022, bytes(70000)),)))
    signed = Message(1, bytes(12), (Attribute(0x0008, bytes(20)),))
    with pytest.raises(StunFormatError, match="already"):
        encode_message(signed, b"key")


@given(
    st.integers(0, 0xFFF),
    st.sampled_from(list(StunClass)),
    st.binary(min_size=12, max_size=12),
    st.lists(st.tuples(st.integers(0, 0xFFFF), st.binary(max_size=40)), max_size=6),
)
def test_roundtrip(method, klass, transaction_id, raw_attributes):
    message = Message(
        make_message_type(method, klass),
        transaction_id,
        tuple(Attribute(t, v) for t, v in raw_attributes),
    )
    assert decode_message(encode_message(message)) == message
