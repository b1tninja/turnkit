"""incremental candidate exchange (RFC 8838).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "encode_end_of_candidates",
]


def encode_end_of_candidates(component: int) -> bytes:
    """Pending behaviour defined by RFC 8838.

    Not implemented yet. See the ``trickle.encode_end_of_candidates()`` row in
    ROADMAP.md; this stub raises on purpose so nothing downstream mistakes it for working
    code.
    """
    raise NotImplementedError("encode_end_of_candidates() is not implemented: RFC 8838")
