"""permissions and channel bindings (RFC 8656).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Allocation = Any  # placeholder: give it a real type in the milestone that needs it
    Permission = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "create_permission",
]


def create_permission(allocation: Allocation, peer: tuple) -> Permission:
    """Pending behaviour defined by RFC 8656 sec. 10.

    Not implemented yet. See the ``permission.create_permission()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("create_permission() is not implemented: RFC 8656 sec. 10")
