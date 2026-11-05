"""turnkit -- STUN, TURN and ICE on asyncio.

The NAT traversal stack has a Python owner, but a narrow one. aioice 0.12.1 (2026-11-03) is
written for aiortc: one ICE agent with a private TURN implementation bolted on, and its own
summary still cites RFC 5245, which RFC 8445 obsoleted in 2018, plus RFC 8863, which changed
when an agent may declare failure. stun 1.1.0 (2026-08-01) is a message library, and pystun3
plus aiostun answer only the NAT-type question. turnkit is the reusable half nobody has: a
TURN client API with its own allocation lifecycle, and an ICE agent whose spec anchors are
the current documents rather than the ones a 2018 codebase inherited.
"""

from __future__ import annotations

from . import (
    allocation,
    apps,
    cli,
    credentials,
    ice,
    message,
    permission,
    sansio,
    transport,
    trickle,
)
from .allocation import allocate, refresh
from .credentials import rest_credentials
from .ice import gather_candidates, schedule_checks
from .message import decode_message, encode_message
from .permission import create_permission
from .sansio import on_binding_response
from .trickle import encode_end_of_candidates

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "allocate",
    "allocation",
    "apps",
    "cli",
    "create_permission",
    "credentials",
    "decode_message",
    "encode_end_of_candidates",
    "encode_message",
    "gather_candidates",
    "ice",
    "message",
    "on_binding_response",
    "permission",
    "refresh",
    "rest_credentials",
    "sansio",
    "schedule_checks",
    "transport",
    "trickle",
]
