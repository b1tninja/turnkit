"""long-term credentials, nonce handling, REST tokens (RFC 8489, RFC 7635).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Credentials = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "rest_credentials",
]


def rest_credentials(username: str, secret: bytes, now: float) -> Credentials:
    """Pending behaviour defined by RFC 7635.

    Not implemented yet. See the ``credentials.rest_credentials()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("rest_credentials() is not implemented: RFC 7635")
