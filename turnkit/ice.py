"""ICE agent: candidates, check scheduling, nomination (RFC 8445).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    AgentState = Any  # placeholder: give it a real type in the milestone that needs it
    Allocation = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "gather_candidates",
    "schedule_checks",
]


def gather_candidates(interfaces: list, relay: Allocation | None) -> list:
    """Pending behaviour defined by RFC 8445.

    Not implemented yet. See the ``ice.gather_candidates()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("gather_candidates() is not implemented: RFC 8445")


def schedule_checks(pairs: list, state: AgentState) -> list:
    """Pending behaviour defined by RFC 8445.

    Not implemented yet. See the ``ice.schedule_checks()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("schedule_checks() is not implemented: RFC 8445")
