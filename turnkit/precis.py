"""OpaqueString (RFC 8265 sec. 4.2) on the PRECIS FreeformClass (RFC 8264 sec. 4.3).

The code point repertoire comes from ``_precis_table.py``, generated from IANA's PRECIS
derived property registry for **Unicode 6.3.0** (the only version the registry carries;
the undated registry URL redirects to it). Provenance (URL, sha256, updated date) is in
that module and in docs/rfc-map.md.

Policy decisions, each pinned by a test:

* **Unassigned means refused.** A code point Unicode 6.3.0 did not assign (emoji added
  since, for one) is UNASSIGNED in the table, and RFC 8264 sec. 4.3.4 says to treat such
  code points as disallowed. The derived property of a newer code point could be computed
  from the Unicode database of the running Python instead; that would let the answer
  change with the interpreter, which a key-derivation input must not, so it is a
  conservative refusal here. ``PrecisError`` says which code point. ``unicode_database=True``
  is the explicit opt-in for the other behaviour (``derived_property_from_database``).
* Order (RFC 8265 sec. 4.2.2): no width mapping, non-ASCII ``Zs`` mapped to SPACE, no case
  mapping, NFC, no directionality rule; then every code point must be allowed.
* CONTEXTJ and CONTEXTO code points (RFC 8264 sec. 4.3.2) are allowed only when the RFC 5892
  appendix A rule holds, evaluated for every occurrence (erratum 3312). The standard
  library has no Script or Joining_Type property, so scripts are read from character
  names (Greek, Hebrew, Hiragana, Katakana and CJK ideographs) and the ZERO WIDTH
  NON-JOINER joining-type pattern is not evaluated: U+200C is accepted only after a
  virama (combining class 9). That refuses some strings the RFC accepts; it never accepts
  one it forbids.
* An empty result is refused: the FreeformClass has no empty string, and an empty
  password or realm would make a key that depends on nothing.

RFC 5769 sec. 2.4 and RFC 8489 appendix B.1 print the password "The<U+00AD>M<U+00AA>tr
<U+2168>" as "TheMatrIX" "after OpaqueString processing". That is SASLprep (RFC 4013, NFKC)
output: OpaqueString keeps U+00AA and U+2168 (HasCompat code points are valid) and refuses
U+00AD (DISALLOWED). The vectors are therefore used with ``prepared=True``.
"""

from __future__ import annotations

import unicodedata
from bisect import bisect_right

from ._precis_table import RANGES
from ._precis_table import UNICODE_VERSION as _UNICODE_VERSION

__all__ = [
    "PrecisError",
    "compare",
    "derived_property",
    "derived_property_from_database",
    "opaque_string",
]

_STARTS = [row[0] for row in RANGES]
_NAMES = {
    "P": "PVALID",
    "F": "ID_DIS or FREE_PVAL",
    "J": "CONTEXTJ",
    "O": "CONTEXTO",
    "D": "DISALLOWED",
    "U": "UNASSIGNED",
}
_ARABIC_INDIC = range(0x0660, 0x066A)
_EXTENDED_ARABIC_INDIC = range(0x06F0, 0x06FA)
_VIRAMA = 9  # Canonical_Combining_Class


class PrecisError(ValueError):
    """The string contains a code point the profile does not allow."""


def derived_property(code_point: int) -> str:
    """The IANA registry's derived property for ``code_point`` under Unicode 6.3.0.

    One of ``PVALID``, ``ID_DIS or FREE_PVAL``, ``CONTEXTJ``, ``CONTEXTO``, ``DISALLOWED``
    or ``UNASSIGNED`` (RFC 8264 sec. 8, registry per sec. 9).
    """
    if not 0 <= code_point <= 0x10FFFF:
        raise ValueError(f"not a code point: {code_point:#x}")
    return _NAMES[RANGES[bisect_right(_STARTS, code_point) - 1][2]]


# RFC 5892 sec. 2.6 (Exceptions, category F), included by RFC 8264 sec. 9.6, with the values
# of the sec. 2.6 tables.
_EXCEPTIONS: dict[int, str] = {
    **dict.fromkeys((0x00DF, 0x03C2, 0x06FD, 0x06FE, 0x0F0B, 0x3007), "PVALID"),
    **dict.fromkeys((0x00B7, 0x0375, 0x05F3, 0x05F4, 0x30FB), "CONTEXTO"),
    **dict.fromkeys((*_ARABIC_INDIC, *_EXTENDED_ARABIC_INDIC), "CONTEXTO"),
    **dict.fromkeys(
        (0x0640, 0x07FA, 0x302E, 0x302F, 0x3031, 0x3032, 0x3033, 0x3034, 0x3035, 0x303B),
        "DISALLOWED",
    ),
}
_FREE_PVAL = "ID_DIS or FREE_PVAL"
# Default_Ignorable_Code_Point members that are not General_Category Cf. The standard library
# has no such property; the Cf members need no list because every Cf code point ends in
# DISALLOWED (test_database_mode_cf_has_no_compatibility_decomposition). The values follow
# DerivedCoreProperties.txt; tests/test_precis.py checks them against that file when a copy
# is in the cache, and skips loudly when it is not.
_DEFAULT_IGNORABLE_NOT_CF = frozenset(
    {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0}
    | set(range(0x180B, 0x1810))
    | set(range(0xFE00, 0xFE10))
    | set(range(0xE0100, 0xE01F0))
)


def _is_noncharacter(code_point: int) -> bool:
    return 0xFDD0 <= code_point <= 0xFDEF or code_point & 0xFFFE == 0xFFFE


def _is_old_hangul_jamo(code_point: int) -> bool:
    # Hangul_Syllable_Type L, V or T: the conjoining jamo blocks (RFC 5892 sec. 2.9)
    return (
        0x1100 <= code_point <= 0x11FF
        or 0xA960 <= code_point <= 0xA97C
        or 0xD7B0 <= code_point <= 0xD7C6
        or 0xD7CB <= code_point <= 0xD7FB
    )


def derived_property_from_database(code_point: int) -> str:
    """The RFC 8264 sec. 8 derived property computed from the running Python's Unicode database.

    This is the opt-in alternative to :func:`derived_property`. Code points assigned after
    Unicode 6.3.0 get a real answer instead of UNASSIGNED, and the answer follows
    ``unicodedata.unidata_version`` of the interpreter, so two interpreters can disagree
    about a newly assigned code point; use it only where that is acceptable. The rule order
    is the sec. 8 algorithm; the categories are sec. 9 and RFC 5892 sec. 2. For every code
    point Unicode 6.3.0 assigned, the result equals the IANA registry's value
    (``test_database_mode_agrees_with_the_registry``).
    """
    if not 0 <= code_point <= 0x10FFFF:
        raise ValueError(f"not a code point: {code_point:#x}")
    if code_point in _EXCEPTIONS:  # Exceptions (F); BackwardCompatible (G) is the empty set
        return _EXCEPTIONS[code_point]
    char = chr(code_point)
    category = unicodedata.category(char)
    if category == "Cn" and not _is_noncharacter(code_point):  # Unassigned (J)
        return "UNASSIGNED"
    if 0x21 <= code_point <= 0x7E:  # ASCII7 (K)
        return "PVALID"
    if code_point in (0x200C, 0x200D):  # JoinControl (H)
        return "CONTEXTJ"
    if _is_old_hangul_jamo(code_point):  # OldHangulJamo (I)
        return "DISALLOWED"
    if (
        _is_noncharacter(code_point)
        or code_point in _DEFAULT_IGNORABLE_NOT_CF
        or category in ("Cf", "Cc")  # PrecisIgnorableProperties (M); Controls (L)
    ):
        return "DISALLOWED"
    if unicodedata.normalize("NFKC", char) != char:  # HasCompat (Q)
        return _FREE_PVAL
    if category in ("Ll", "Lu", "Lo", "Nd", "Lm", "Mn", "Mc"):  # LetterDigits (A)
        return "PVALID"
    if category in ("Lt", "Nl", "No", "Me", "Zs") or category[0] in "SP":  # R, N, O, P
        return _FREE_PVAL
    return "DISALLOWED"


def _name(char: str) -> str:
    return unicodedata.name(char, "")


def _is_han_or_kana(char: str) -> bool:
    if ord(char) == 0x30FB:
        return False
    name = _name(char)
    return name.startswith(("HIRAGANA", "KATAKANA", "CJK UNIFIED", "CJK COMPATIBILITY IDEOGRAPH"))


def _context_ok(text: str, index: int) -> bool:
    """RFC 5892 appendix A for the CONTEXTJ or CONTEXTO code point at ``index``."""
    code = ord(text[index])
    before = text[index - 1] if index > 0 else ""
    after = text[index + 1] if index + 1 < len(text) else ""
    if code in (0x200C, 0x200D):  # A.1, A.2: only the virama branch is evaluated
        return bool(before) and unicodedata.combining(before) == _VIRAMA
    if code == 0x00B7:  # A.3: between two 'l'
        return before == "l" and after == "l"
    if code == 0x0375:  # A.4: followed by Greek
        return bool(after) and _name(after).startswith("GREEK")
    if code in (0x05F3, 0x05F4):  # A.5, A.6: preceded by Hebrew
        return bool(before) and _name(before).startswith("HEBREW")
    if code == 0x30FB:  # A.7: some Hiragana, Katakana or Han in the string
        return any(_is_han_or_kana(c) for c in text)
    if code in _ARABIC_INDIC:  # A.8
        return not any(ord(c) in _EXTENDED_ARABIC_INDIC for c in text)
    if code in _EXTENDED_ARABIC_INDIC:  # A.9
        return not any(ord(c) in _ARABIC_INDIC for c in text)
    return False


def opaque_string(text: str, *, unicode_database: bool = False) -> str:
    """Enforce the OpaqueString profile on ``text`` (RFC 8265 sec. 4.2.2); return the result.

    Raises :class:`PrecisError` for a code point the FreeformClass does not allow, for a
    contextual rule that fails, and for an empty result. Case is preserved.

    The default judges code points by the IANA Unicode 6.3.0 registry and refuses later
    assignments. ``unicode_database=True`` is the opt-in that computes the derived property
    from the running interpreter's Unicode database instead
    (:func:`derived_property_from_database`), so emoji and scripts assigned since 6.3.0 are
    accepted, and the answer for those can differ between Python versions.
    """
    lookup = derived_property_from_database if unicode_database else derived_property
    version = unicodedata.unidata_version if unicode_database else _UNICODE_VERSION
    mapped = "".join(
        " " if c != " " and unicodedata.category(c) == "Zs" else c for c in text
    )  # sec. 4.2.2 rule 2
    result = unicodedata.normalize("NFC", mapped)  # rule 4
    if not result:
        raise PrecisError("an OpaqueString is never empty")
    for index, char in enumerate(result):
        kind = lookup(ord(char))
        if kind in ("PVALID", "ID_DIS or FREE_PVAL"):
            continue
        if kind in ("CONTEXTJ", "CONTEXTO") and _context_ok(result, index):
            continue
        raise PrecisError(f"U+{ord(char):04X} is {kind} in the FreeformClass (Unicode {version})")
    return result


def compare(first: str, second: str, *, unicode_database: bool = False) -> bool:
    """RFC 8265 sec. 4.2.3: enforce both strings, then equal only if the octets are equal."""
    one = opaque_string(first, unicode_database=unicode_database)
    two = opaque_string(second, unicode_database=unicode_database)
    return one.encode("utf-8") == two.encode("utf-8")
