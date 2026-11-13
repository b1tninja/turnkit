"""PRECIS OpaqueString (RFC 8265 sec. 4.2) over the generated IANA Unicode 6.3.0 table."""

from __future__ import annotations

import itertools
import re
import unicodedata

import pytest

from turnkit import _precis_table, precis
from turnkit.precis import PrecisError, compare, derived_property, opaque_string


def test_table_covers_every_code_point_once_and_carries_provenance():
    ranges = _precis_table.RANGES
    assert ranges[0][0] == 0
    assert ranges[-1][1] == 0x10FFFF
    for (_, previous_end, _), (start, end, _) in itertools.pairwise(ranges):
        assert start == previous_end + 1
        assert start <= end
    assert re.fullmatch(r"[0-9a-f]{64}", _precis_table.SOURCE_SHA256)
    assert _precis_table.SOURCE_URL.startswith("https://www.iana.org/assignments/precis-tables")
    assert _precis_table.UNICODE_VERSION == "6.3.0"
    assert len(ranges) == 1502  # the registry's record count: nothing was merged or lost


@pytest.mark.parametrize(
    ("code_point", "expected"),
    [
        (0x41, "PVALID"),
        (0x20, "ID_DIS or FREE_PVAL"),
        (0xA0, "ID_DIS or FREE_PVAL"),
        (0xAD, "DISALLOWED"),
        (0x00B7, "CONTEXTO"),
        (0x200C, "CONTEXTJ"),
        (0x0378, "UNASSIGNED"),
        (0x1F600, "ID_DIS or FREE_PVAL"),  # emoticons were assigned in Unicode 6.1
        (0x1F9D0, "UNASSIGNED"),  # assigned in Unicode 10.0, after the table's version
        (0x10FFFF, "DISALLOWED"),
    ],
)
def test_derived_property_spot_checks(code_point, expected):
    assert derived_property(code_point) == expected


def test_table_agrees_with_the_unicode_database_it_can_check():
    # a code point the running Python (newer than 6.3.0) calls unassigned can only be
    # UNASSIGNED here, or DISALLOWED for the noncharacters
    for code in range(0x110000):
        category = unicodedata.category(chr(code))
        if category == "Cn":
            noncharacter = 0xFDD0 <= code <= 0xFDEF or code & 0xFFFE == 0xFFFE
            assert derived_property(code) == ("DISALLOWED" if noncharacter else "UNASSIGNED"), code
        elif category in ("Cc", "Cs", "Co"):
            assert derived_property(code) in ("DISALLOWED", "UNASSIGNED"), code


def test_opaque_string_vectors():
    # ASCII is unchanged and case is preserved (sec. 4.2.2 rule 3)
    assert opaque_string("Pa ss~W0rd!") == "Pa ss~W0rd!"
    # NFC composes (rule 4) and leaves composed text alone
    assert opaque_string("pa\u0308ssword") == "p\u00e4ssword" == opaque_string("p\u00e4ssword")
    # non-ASCII spaces become SPACE (rule 2)
    assert opaque_string("a\u00a0b\u3000c\u2003d") == "a b c d"
    # no width mapping (rule 1): fullwidth text is kept as written
    assert opaque_string("\uff21\uff11") == "\uff21\uff11"
    # no compatibility mapping: HasCompat code points are valid as they are (the SASLprep
    # result "TheMatrIX" of RFC 5769 sec. 2.4 is NOT what OpaqueString produces)
    assert opaque_string("The\u00aatr\u2168") == "The\u00aatr\u2168"
    with pytest.raises(PrecisError, match=r"U\+00AD"):
        opaque_string("The\u00adM\u00aatr\u2168")
    # the RFC 5769 username is valid and unchanged
    username = "\u30de\u30c8\u30ea\u30c3\u30af\u30b9"
    assert opaque_string(username) == username


def test_opaque_string_refusals():
    for bad in ("a\x00b", "a\x7fb", "tab\tinside", "\ufdd0", "\U0001f9d0", "a\u200bb", ""):
        with pytest.raises(PrecisError):
            opaque_string(bad)
    assert issubclass(PrecisError, ValueError)


def test_comparison_is_octet_equality_after_enforcement():
    assert compare("a\u00a0b", "a b")
    assert compare("p\u00e4", "pa\u0308")
    assert not compare("Pass", "pass")  # no case mapping


def test_contextual_rules_are_evaluated_per_occurrence():
    assert opaque_string("l\u00b7l") == "l\u00b7l"
    for bad in ("a\u00b7l", "l\u00b7", "\u00b7l"):
        with pytest.raises(PrecisError, match="CONTEXTO"):
            opaque_string(bad)
    assert opaque_string("l\u00b7l and l\u00b7l")
    with pytest.raises(PrecisError):
        opaque_string("l\u00b7l and a\u00b7l")  # one bad occurrence fails the string
    assert opaque_string("\u0375\u03b1")  # keraia before a Greek letter
    with pytest.raises(PrecisError):
        opaque_string("\u0375a")
    assert opaque_string("\u05d0\u05f3")  # geresh after a Hebrew letter
    with pytest.raises(PrecisError):
        opaque_string("a\u05f3")
    assert opaque_string("a\u30fb\u30a2")  # katakana middle dot with a katakana letter
    with pytest.raises(PrecisError):
        opaque_string("a\u30fbb")
    assert opaque_string("\u0661\u0662")
    with pytest.raises(PrecisError):
        opaque_string("\u0661\u06f1")  # Arabic-Indic mixed with Extended
    # joiners: after a virama only (the joining-type branch is not evaluated)
    assert opaque_string("\u0915\u094d\u200d\u0937")
    with pytest.raises(PrecisError):
        opaque_string("a\u200db")


def test_module_surface():
    assert set(precis.__all__) == {"PrecisError", "compare", "derived_property", "opaque_string"}
