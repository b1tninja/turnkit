"""STUN message, attribute and integrity codec (RFC 8489).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    StunMessage = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_message",
    "encode_message",
]


def encode_message(msg: StunMessage, key: bytes | None) -> bytes:
    """Pending behaviour defined by RFC 8489 sec. 5, sec. 14.

    Not implemented yet. See the ``message.encode_message()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_message() is not implemented: RFC 8489 sec. 5, sec. 14")


def decode_message(raw: bytes) -> StunMessage:
    """Pending behaviour defined by RFC 8489 sec. 5, sec. 14.

    Not implemented yet. See the ``message.decode_message()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_message() is not implemented: RFC 8489 sec. 5, sec. 14")
