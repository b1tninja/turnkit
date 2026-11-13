"""Byte vectors transcribed from RFC 5769 section 2 (read through rfclib on 2026-11-13).

Whitespace in the hex is for reading; ``bytes.fromhex`` ignores it. The padding bytes in
2.1, 2.2 and 2.3 are spaces, in 2.4 they are NUL: the RFC says padding may take any value.
"""

from __future__ import annotations

# 2.1 Sample Request. Short-term password "VOkJxbRl1RmTxUk/WvJxBt".
SAMPLE_REQUEST = bytes.fromhex(
    "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e20746573742063 6c69656e74"
    "00240004"
    "6e0001ff"
    "80290008"
    "932ff9b151263b36"
    "00060009"
    "6576746a3a683676"
    "59202020"
    "00080014"
    "9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2"
    "80280004"
    "e57a3bcf"
)

# 2.2 Sample IPv4 Response: mapped address 192.0.2.1 port 32853.
SAMPLE_IPV4_RESPONSE = bytes.fromhex(
    "0101003c2112a442b7e7a701bc34d686fa87dfae"
    "8022000b"
    "7465737420766563746f7220"
    "00200008"
    "0001a147e112a643"
    "00080014"
    "2b91f599fd9e90c38c7489f92af9ba53f06be7d7"
    "80280004"
    "c07d4c96"
)

# 2.3 Sample IPv6 Response: mapped address 2001:db8:1234:5678:11:2233:4455:6677 port 32853.
SAMPLE_IPV6_RESPONSE = bytes.fromhex(
    "010100482112a442b7e7a701bc34d686fa87dfae"
    "8022000b"
    "7465737420766563746f7220"
    "00200014"
    "0002a14701 13a9faa5d3f179bc25f4b5bed2b9d9"
    "00080014"
    "a382954e4be67bf11784c97c8292c275bfe3ed41"
    "80280004"
    "c8fb0b4c"
)

# 2.4 Sample Request with Long-Term Authentication. Username is the katakana string
# U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9; password "TheMatrIX" after SASLprep.
LONG_TERM_REQUEST = bytes.fromhex(
    "000100602112a44278ad3433c6ad72c029da412e"
    "00060012"
    "e3839ee38388e383aae38383e382afe382b90000"
    "0015001c"
    "662f2f3439396b3935346436"
    "4f4c33346f4c394653547679"
    "3634 7341"
    "0014000b"
    "6578616d706c652e6f726700"
    "00080014"
    "f67024656dd64a3e02b8e0712e85c9a28ca89666"
)

PASSWORD = "VOkJxbRl1RmTxUk/WvJxBt"
TRANSACTION_ID = bytes.fromhex("b7e7a701bc34d686fa87dfae")
LONG_TERM_USERNAME = "マトリックス"
LONG_TERM_REALM = "example.org"
LONG_TERM_PASSWORD = "TheMatrIX"
