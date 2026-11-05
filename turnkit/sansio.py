"""pure agent core for virtual clock testing.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    AgentState = Any  # placeholder: give it a real type in the milestone that needs it
    Received = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "on_binding_response",
]


def on_binding_response(event: Received, now: float) -> AgentState:
    """Pending behaviour defined by RFC 8445, RFC 8863.

    Not implemented yet. See the ``sansio.on_binding_response()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("on_binding_response() is not implemented: RFC 8445, RFC 8863")
