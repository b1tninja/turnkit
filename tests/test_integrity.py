"""MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256, FINGERPRINT and the keys, against the RFC vectors."""

from __future__ import annotations

import hashlib
import hmac
import struct

import pytest

from tests.vectors import (
    LONG_TERM_PASSWORD,
    LONG_TERM_REALM,
    LONG_TERM_REQUEST,
    LONG_TERM_USERNAME,
    PASSWORD,
    SAMPLE_IPV4_RESPONSE,
    SAMPLE_IPV6_RESPONSE,
    SAMPLE_REQUEST,
)
from turnkit import credentials, integrity
from turnkit.integrity import (
    check_fingerprint,
    check_message_integrity,
    fingerprint_value,
    message_integrity_value,
)
from turnkit.message import Attribute, Message, decode_message, encode_message
from turnkit.wire import scan

KEY = credentials.short_term_key(PASSWORD)
VECTORS = [SAMPLE_REQUEST, SAMPLE_IPV4_RESPONSE, SAMPLE_IPV6_RESPONSE]


def locate(data: bytes, attribute_type: int) -> int:
    """Header offset of the first attribute of a type."""
    for found, offset, _ in scan(data):
        if found == attribute_type:
            return offset
    raise AssertionError("attribute not in the vector")


def test_rfc5769_hmac_sha1():
    # 2.1, 2.2 and 2.3: the HMAC covers everything before MESSAGE-INTEGRITY with the length
    # field rewritten to end at MESSAGE-INTEGRITY, although FINGERPRINT follows it.
    for vector in VECTORS:
        offset = locate(vector, integrity.MESSAGE_INTEGRITY)
        assert message_integrity_value(vector[:offset], KEY) == vector[offset + 4 : offset + 24]


def test_rfc5769_fingerprint():
    for vector in VECTORS:
        offset = locate(vector, integrity.FINGERPRINT)
        assert fingerprint_value(vector[:offset]) == vector[offset + 4 : offset + 8]
        assert check_fingerprint(vector)


def test_length_adjustment_with_fingerprint_present():
    # Hashing with the final length (the common bug) does not reproduce the RFC's value.
    vector = SAMPLE_REQUEST
    offset = locate(vector, integrity.MESSAGE_INTEGRITY)
    wrong = hmac.new(KEY, vector[:offset], hashlib.sha1).digest()
    assert wrong != vector[offset + 4 : offset + 24]


def test_verify_accepts_vectors():
    for vector in VECTORS:
        assert check_message_integrity(vector, KEY)
        assert check_fingerprint(vector)


def test_wrong_key_rejected():
    for vector in VECTORS:
        assert not check_message_integrity(vector, credentials.short_term_key("not the password"))


def test_rfc5769_long_term_vector_with_the_prepared_password():
    # 2.4: the password is "The<U+00AD>M<U+00AA>tr<U+2168>" before SASLprep, "TheMatrIX" after.
    key = credentials.long_term_key(
        LONG_TERM_USERNAME, LONG_TERM_REALM, LONG_TERM_PASSWORD, prepared=True
    )
    assert len(key) == 16
    assert check_message_integrity(LONG_TERM_REQUEST, key)
    # the unprepared form is a different key, which is why preparation matters
    unprepared = credentials.long_term_key(
        LONG_TERM_USERNAME, LONG_TERM_REALM, "The­MªtrⅨ", prepared=True
    )
    assert not check_message_integrity(LONG_TERM_REQUEST, unprepared)


def test_rfc8489_b1_userhash():
    expected = bytes.fromhex("4a3cf38fef6992bda952c6780417da0f24819415569e60b205c46e41407f1704")
    assert credentials.userhash(LONG_TERM_USERNAME, LONG_TERM_REALM, prepared=True) == expected


def test_rfc8489_b1_printed_vector_only_matches_the_erroneous_length():
    # Erratum 6268 (verified): the printed header length 0x9c counts the 20-byte header (and
    # the vector lacks PASSWORD-ALGORITHM). The printed MESSAGE-INTEGRITY-SHA256 is
    # reproducible only by hashing with that wrong length, never with the correct one.
    def attribute(attr_type: int, value: bytes) -> bytes:
        return struct.pack(">HH", attr_type, len(value)) + value + bytes(-len(value) % 4)

    userhash = credentials.userhash(LONG_TERM_USERNAME, LONG_TERM_REALM, prepared=True)
    body = (
        attribute(0x001E, userhash)
        + attribute(0x0015, b"obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA")
        + attribute(0x0014, b"example.org")
    )
    header = struct.pack(">HHI", 0x0001, len(body), 0x2112A442)
    header += bytes.fromhex("78ad3433c6ad72c029da412e")
    printed = bytes.fromhex("e4686c8f0edeb59013e07090010a93efccbccc544c0a45d9f830aa6d6f735a01")
    key = credentials.long_term_key(
        LONG_TERM_USERNAME, LONG_TERM_REALM, LONG_TERM_PASSWORD, credentials.SHA256, prepared=True
    )
    assert len(key) == 32
    assert message_integrity_value(header + body, key, "sha256") != printed  # correct length
    erroneous = header[:2] + b"\x00\x9c" + header[4:] + body
    assert hmac.new(key, erroneous, hashlib.sha256).digest() == printed  # the printed 0x9c


def test_verify_rejects_one_bit_flip_in_every_byte_before_integrity():
    offset = locate(SAMPLE_REQUEST, integrity.MESSAGE_INTEGRITY)
    for position in range(offset):
        flipped = bytearray(SAMPLE_REQUEST)
        flipped[position] ^= 0x01
        assert not check_message_integrity(bytes(flipped), KEY), position


def test_flip_after_integrity_fails_only_the_fingerprint():
    flipped = bytearray(SAMPLE_REQUEST)
    flipped[-1] ^= 0x01
    assert check_message_integrity(bytes(flipped), KEY)
    assert not check_fingerprint(bytes(flipped))


def test_fingerprint_not_last_refused():
    message = decode_message(SAMPLE_REQUEST)
    attributes = (*message.attributes, Attribute(0x8022, b"after"))
    reordered = encode_message(Message(message.message_type, message.transaction_id, attributes))
    assert not check_fingerprint(reordered)
    unsigned = encode_message(Message(1, bytes(12), (Attribute(0x8022, b"x"),)))
    assert not check_fingerprint(unsigned) and not check_message_integrity(unsigned, KEY)


def test_encode_signs_and_verifies_both_algorithms():
    message = Message(0x0001, bytes(range(12)), (Attribute(0x0006, b"user"),))
    for algorithm in ("sha1", "sha256"):
        key = credentials.long_term_key("user", "realm", "pass", credentials.SHA256)
        raw = encode_message(message, key, integrity=algorithm, fingerprint=True)
        assert check_message_integrity(raw, key, algorithm)
        assert check_fingerprint(raw)
        assert raw[2:4] == struct.pack(">H", len(raw) - 20)
        assert not check_message_integrity(raw, b"other", algorithm)
    plain = encode_message(message, b"k", fingerprint=True)
    assert [a.type for a in decode_message(plain).attributes] == [0x0006, 0x0008, 0x8028]


def test_sha256_lengths_are_16_to_32_in_multiples_of_four():
    for good in (16, 20, 32):
        assert len(message_integrity_value(b"\x00" * 20, b"k", "sha256", good)) == good
    for bad in (12, 15, 17, 36, 0):
        with pytest.raises(ValueError, match="16 to 32"):
            message_integrity_value(b"\x00" * 20, b"k", "sha256", bad)
    with pytest.raises(ValueError, match="20 octets"):
        message_integrity_value(b"\x00" * 20, b"k", "sha1", 16)


def test_truncated_sha256_value_is_checked_against_its_own_length():
    message = Message(0x0001, bytes(12))
    prefix = encode_message(message)
    value = message_integrity_value(prefix, b"k", "sha256", 16)
    raw = prefix + struct.pack(">HH", 0x001C, 16) + value
    raw = raw[:2] + struct.pack(">H", len(raw) - 20) + raw[4:]
    assert check_message_integrity(raw, b"k", "sha256")
    assert not check_message_integrity(raw, b"j", "sha256")


def test_constant_time_compare(monkeypatch):
    calls = []
    real = hmac.compare_digest

    def counting(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(integrity.hmac, "compare_digest", counting)
    check_message_integrity(SAMPLE_REQUEST, KEY)
    check_fingerprint(SAMPLE_REQUEST)
    assert len(calls) == 2


def test_only_the_first_message_integrity_counts():
    # a hostile duplicate after the real one does not change the verdict
    first = SAMPLE_REQUEST[: locate(SAMPLE_REQUEST, integrity.MESSAGE_INTEGRITY) + 24]
    forged = first + struct.pack(">HH", 0x0008, 20) + bytes(20)
    forged = forged[:2] + struct.pack(">H", len(forged) - 20) + forged[4:]
    assert check_message_integrity(forged, KEY)


def test_keys_from_the_rfc_examples():
    # RFC 8489 sec. 9.2.2 prints the MD5 of 'user:realm:pass'
    assert credentials.long_term_key("user", "realm", "pass").hex() == (
        "8493fbc53ba582fb4c044c456bdc40eb"
    )
    assert len(credentials.long_term_key("user", "realm", "pass", credentials.SHA256)) == 32
    assert credentials.short_term_key("pw") == b"pw"
    assert credentials.opaque_string("pässword") == "pässword"
    with pytest.raises(ValueError, match=r"U\+0000"):
        credentials.opaque_string("a\x00b")
    with pytest.raises(ValueError, match="unknown password algorithm"):
        credentials.long_term_key("u", "r", "p", 0x0003)


def test_opaque_string_vectors():
    # non-ASCII credentials are prepared, not refused: NFC composes and a non-ASCII space
    # maps to SPACE, so equal-looking inputs give one key
    assert credentials.opaque_string("pa\u0308ss\u00a0word") == "p\u00e4ss word"
    decomposed = credentials.long_term_key("user", "realm", "pa\u0308ss")
    assert decomposed == credentials.long_term_key("user", "realm", "p\u00e4ss")
    assert decomposed != credentials.long_term_key("user", "realm", "pass")
    name = "\u30de\u30c8"
    assert credentials.userhash(name, "example.org") == credentials.userhash(
        name, "example.org", prepared=True
    )
    # the RFC 5769 sec. 2.4 password is SASLprep's input, not valid OpaqueString input
    with pytest.raises(ValueError, match=r"U\+00AD"):
        credentials.short_term_key("The\u00adM\u00aatr\u2168")
