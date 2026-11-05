"""TURN allocate, refresh, lifetime and reallocation (RFC 8656).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Allocation = Any  # placeholder: give it a real type in the milestone that needs it
    Credentials = Any  # placeholder: give it a real type in the milestone that needs it
    Endpoint = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "allocate",
    "refresh",
]


async def allocate(server: Endpoint, credentials: Credentials) -> Allocation:
    """Pending behaviour defined by RFC 8656.

    Not implemented yet. See the ``allocation.allocate()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("allocate() is not implemented: RFC 8656")


async def refresh(allocation: Allocation) -> Allocation:
    """Pending behaviour defined by RFC 8656.

    Not implemented yet. See the ``allocation.refresh()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("refresh() is not implemented: RFC 8656")
