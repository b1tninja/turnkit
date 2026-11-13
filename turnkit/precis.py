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
  conservative refusal here. ``PrecisError`` says which code point.
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

__all__ = [
    "PrecisError",
    "compare",
    "derived_property",
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


def opaque_string(text: str) -> str:
    """Enforce the OpaqueString profile on ``text`` (RFC 8265 sec. 4.2.2); return the result.

    Raises :class:`PrecisError` for a code point the FreeformClass does not allow, for a
    contextual rule that fails, and for an empty result. Case is preserved.
    """
    mapped = "".join(
        " " if c != " " and unicodedata.category(c) == "Zs" else c for c in text
    )  # sec. 4.2.2 rule 2
    result = unicodedata.normalize("NFC", mapped)  # rule 4
    if not result:
        raise PrecisError("an OpaqueString is never empty")
    for index, char in enumerate(result):
        kind = derived_property(ord(char))
        if kind in ("PVALID", "ID_DIS or FREE_PVAL"):
            continue
        if kind in ("CONTEXTJ", "CONTEXTO") and _context_ok(result, index):
            continue
        raise PrecisError(f"U+{ord(char):04X} is {kind} in the FreeformClass (Unicode 6.3.0)")
    return result


def compare(first: str, second: str) -> bool:
    """RFC 8265 sec. 4.2.3: enforce both strings, then equal only if the octets are equal."""
    return opaque_string(first).encode("utf-8") == opaque_string(second).encode("utf-8")
