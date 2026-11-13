"""The client side of a TURN allocation as pure state (RFC 8656 sec. 7 and sec. 8).

No I/O and no clock of its own: the caller builds requests from the attribute lists here,
sends them (see :mod:`turnkit.transport` for the timing), feeds each decoded response to the
client and acts on the :class:`Decision` it returns. Authentication (the 401 and 438
exchange of the long-term credential mechanism) is reported as a decision; computing
MESSAGE-INTEGRITY is :mod:`turnkit.integrity`.

Policy decisions, each pinned by a test in ``tests/test_lifecycle.py``:

* The client MUSTs of sec. 7.1 are checked when a request is built, not left to the
  server: REQUESTED-ADDRESS-FAMILY and ADDITIONAL-ADDRESS-FAMILY never together, neither
  beside a RESERVATION-TOKEN, EVEN-PORT with R=1 never beside ADDITIONAL-ADDRESS-FAMILY,
  and a RESERVATION-TOKEN never beside EVEN-PORT.
* Retry and wait rules are those of sec. 7.4 and sec. 8.3: 437 tries up to three other
  5-tuples then waits 2 minutes; 486 and 508 wait at least 1 minute (508 with EVEN-PORT or
  RESERVATION-TOKEN may retry at once without it); 440 is never retried; 420 for
  DONT-FRAGMENT retries without it; 438 retries with the new nonce; 300 goes to the
  ALTERNATE-SERVER first.
* A second 401 after the client has already authenticated is a rejection of its
  credentials, not a reason to try again. A run of more than three 438 answers in a row is
  also given up: the RFC does not bound that loop, so the bound is ours.
* An Allocate success whose addresses are in a family the client does not handle makes the
  client delete the allocation at once (sec. 7.3).
* A Refresh with lifetime 0 is a delete; a 437 answer to a delete counts as success, and a
  437 answer to an ordinary refresh means the allocation is gone (sec. 8.3).

The server-side rules are here only as :func:`desired_lifetime`, because a test needs the
arithmetic of sec. 7.2 and sec. 8.2 on both sides of the wire.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .attributes import (
    ALTERNATE_SERVER,
    ERROR_CODE,
    FAMILY_IPV4,
    FAMILY_IPV6,
    NONCE,
    REALM,
    UNKNOWN_ATTRIBUTES,
    XOR_MAPPED_ADDRESS,
    decode_error_code,
    decode_unknown_attributes,
    mapped_address,
    xor_mapped_address,
)
from .message import Attribute, Message, StunClass
from .turn_attributes import (
    ADDRESS_ERROR_CODE,
    ALLOCATE,
    DONT_FRAGMENT,
    EVEN_PORT,
    LIFETIME,
    REFRESH,
    RESERVATION_TOKEN,
    XOR_RELAYED_ADDRESS,
    decode_address_error_code,
    decode_lifetime,
    decode_reservation_token,
    encode_additional_address_family,
    encode_dont_fragment,
    encode_even_port,
    encode_lifetime,
    encode_requested_address_family,
    encode_requested_transport,
    encode_reservation_token,
)

__all__ = [
    "DEFAULT_LIFETIME",
    "MAX_LIFETIME",
    "REFRESH_LEAD",
    "Action",
    "AllocationClient",
    "Decision",
    "Phase",
    "allocate_attributes",
    "delete_attributes",
    "desired_lifetime",
    "refresh_attributes",
]

DEFAULT_LIFETIME = 600  # sec. 3.2 and sec. 6: 10 minutes
MAX_LIFETIME = 3600  # sec. 7.2: RECOMMENDED server maximum
REFRESH_LEAD = 60.0  # sec. 8: refresh roughly 1 minute before expiry
_TUPLE_TRIES = 3  # sec. 7.4, 437
_STALE_NONCE_TRIES = 3  # our bound, see the module docstring


def desired_lifetime(
    requested: int | None, default: int = DEFAULT_LIFETIME, maximum: int = MAX_LIFETIME
) -> int:
    """The lifetime a server grants (sec. 7.2 para 8, sec. 8.2 para 3).

    No LIFETIME gives the default; zero gives zero (a Refresh deletes; in an Allocate the
    server ignores values below the default, so callers pass zero only to a Refresh);
    otherwise the smaller of the request and the maximum, but never below the default.
    """
    if requested is None:
        return default
    if requested == 0:
        return 0
    return max(min(requested, maximum), default)


def allocate_attributes(
    *,
    family: int | None = None,
    additional_ipv6: bool = False,
    lifetime: int | None = None,
    dont_fragment: bool = False,
    even_port: bool | None = None,
    reservation_token: bytes | None = None,
) -> tuple[Attribute, ...]:
    """The attributes of an Allocate request (sec. 7.1), refusing combinations it forbids.

    ``even_port`` is ``None`` for no EVEN-PORT, else the R bit. REQUESTED-TRANSPORT is
    always UDP.
    """
    if family is not None and additional_ipv6:
        raise ValueError("REQUESTED-ADDRESS-FAMILY and ADDITIONAL-ADDRESS-FAMILY together")
    if reservation_token is not None:
        if family is not None or additional_ipv6:
            raise ValueError("an address family attribute beside RESERVATION-TOKEN")
        if even_port is not None:
            raise ValueError("EVEN-PORT beside RESERVATION-TOKEN")
    if additional_ipv6 and even_port:
        raise ValueError("EVEN-PORT with R=1 beside ADDITIONAL-ADDRESS-FAMILY")
    attributes = [encode_requested_transport()]
    if family is not None:
        attributes.append(encode_requested_address_family(family))
    if additional_ipv6:
        attributes.append(encode_additional_address_family())
    if lifetime is not None:
        attributes.append(encode_lifetime(lifetime))
    if dont_fragment:
        attributes.append(encode_dont_fragment())
    if even_port is not None:
        attributes.append(encode_even_port(even_port))
    if reservation_token is not None:
        attributes.append(encode_reservation_token(reservation_token))
    return tuple(attributes)


def refresh_attributes(
    *, lifetime: int | None = None, family: int | None = None
) -> tuple[Attribute, ...]:
    """The attributes of a Refresh request (sec. 8.1); ``family`` names one half of a dual allocation."""
    attributes: list[Attribute] = []
    if lifetime is not None:
        attributes.append(encode_lifetime(lifetime))
    if family is not None:
        attributes.append(encode_requested_address_family(family))
    return tuple(attributes)


def delete_attributes(*, family: int | None = None) -> tuple[Attribute, ...]:
    """A Refresh that deletes: LIFETIME zero (sec. 8.1), optionally for one address family."""
    return refresh_attributes(lifetime=0, family=family)


class Phase(Enum):
    """Where the client's allocation stands."""

    IDLE = "idle"
    ALLOCATING = "allocating"
    ACTIVE = "active"
    DELETING = "deleting"
    CLOSED = "closed"
    FAILED = "failed"


class Action(Enum):
    """What the caller does next."""

    ACTIVE = "active"  # allocation made or refreshed; schedule the next refresh
    RETRY_AUTH = "retry_auth"  # repeat the request with credentials (realm and nonce kept)
    RETRY_NEW_NONCE = "retry_new_nonce"  # repeat with the nonce the 438 carried
    NEW_TUPLE = "new_tuple"  # repeat from a different client transport address
    TRY_ALTERNATE = "try_alternate"  # repeat at ``Decision.alternate``
    RETRY_WITHOUT = "retry_without"  # repeat without the attribute types in ``drop``
    BACKOFF = "backoff"  # do not allocate on this server for ``Decision.wait`` seconds
    DELETE = "delete"  # send a Refresh with LIFETIME zero
    CLOSED = "closed"  # the allocation is gone
    GIVE_UP = "give_up"  # failed; do not retry on this server until the cause is fixed


@dataclass(frozen=True)
class Decision:
    """The client's answer to one response."""

    action: Action
    wait: float = 0.0
    reason: str = ""
    alternate: tuple[str, int] | None = None
    drop: frozenset[int] = frozenset()


@dataclass
class AllocationClient:
    """Tracks one allocation from the first Allocate to its deletion.

    ``families`` is the set of address families (0x01, 0x02) the client can use. Time is
    whatever clock the caller keeps, in seconds.
    """

    families: frozenset[int] = frozenset({FAMILY_IPV4, FAMILY_IPV6})
    phase: Phase = Phase.IDLE
    relayed: list[tuple[str, int]] = field(default_factory=list)
    mapped: tuple[str, int] | None = None
    lifetime: int = 0
    expires_at: float = 0.0
    reservation_token: bytes | None = None
    realm: bytes | None = None
    nonce: bytes | None = None
    tuple_tries: int = 0
    backoff_until: float = 0.0
    partial_failures: list[tuple[int, int]] = field(default_factory=list)
    _authenticated: bool = False
    _stale_nonces: int = 0
    _sent_even_port_or_token: bool = False

    def start_allocate(self, attributes: tuple[Attribute, ...], now: float) -> None:
        """Note that an Allocate request built from ``attributes`` is about to be sent."""
        if self.phase in (Phase.ACTIVE, Phase.DELETING):
            raise ValueError("an allocation exists on this 5-tuple already")
        if now < self.backoff_until:
            raise ValueError(f"must not allocate before {self.backoff_until}")
        self._sent_even_port_or_token = any(
            a.type in (EVEN_PORT, RESERVATION_TOKEN) for a in attributes
        )
        self.phase = Phase.ALLOCATING

    def start_delete(self) -> tuple[Attribute, ...]:
        """Begin deleting; returns the Refresh attributes (sec. 8.1)."""
        if self.phase is not Phase.ACTIVE:
            raise ValueError("there is no active allocation to delete")
        self.phase = Phase.DELETING
        return delete_attributes()

    def refresh_due(self, now: float, lead: float = REFRESH_LEAD) -> bool:
        """True from ``lead`` seconds before expiry (sec. 8: roughly 1 minute)."""
        return self.phase is Phase.ACTIVE and now >= self.expires_at - lead

    def has_expired(self, now: float) -> bool:
        """True once the time-to-expiry has run out without a refresh."""
        return self.phase is Phase.ACTIVE and now >= self.expires_at

    # responses -------------------------------------------------------------------------

    def on_allocate_response(self, message: Message, now: float) -> Decision:
        """Process the response to an Allocate request (sec. 7.3, sec. 7.4)."""
        self._expect(message, ALLOCATE, Phase.ALLOCATING)
        if message.klass is StunClass.SUCCESS:
            return self._allocated(message, now)
        return self._allocate_error(message, now)

    def on_refresh_response(self, message: Message, now: float) -> Decision:
        """Process the response to a Refresh request (sec. 8.3)."""
        deleting = self.phase is Phase.DELETING
        self._expect(message, REFRESH, Phase.ACTIVE if not deleting else Phase.DELETING)
        if message.klass is StunClass.SUCCESS:
            attribute = message.find(LIFETIME)
            granted = decode_lifetime(attribute.value) if attribute else 0
            if deleting or granted == 0:
                return self._close("deleted")
            self.lifetime, self.expires_at = granted, now + granted
            self._stale_nonces = 0
            return Decision(Action.ACTIVE, reason="refreshed")
        code, _ = self._error(message)
        if code == 437:  # sec. 8.3: gone; for a delete, as good as success
            return self._close("allocation mismatch on delete" if deleting else "allocation lost")
        if code == 438:
            return self._stale_nonce(message)
        if code == 401 and not self._authenticated:
            return self._challenge(message)
        return self._fail(f"refresh refused with {code}")

    def on_timeout(self) -> Decision:
        """The transaction timed out (408 in sec. 7.4: the server or the path is at fault)."""
        if self.phase is Phase.DELETING:
            return self._fail("no answer to the delete; the allocation will expire")
        return self._fail("no answer from the server")

    # internals -------------------------------------------------------------------------

    def _expect(self, message: Message, method: int, phase: Phase) -> None:
        if message.method != method or message.klass not in (StunClass.SUCCESS, StunClass.ERROR):
            raise ValueError("not a response to this request")
        if self.phase is not phase:
            raise ValueError(f"unexpected response while {self.phase.value}")

    @staticmethod
    def _error(message: Message) -> tuple[int, str]:
        attribute = message.find(ERROR_CODE)
        if attribute is None:
            raise ValueError("an error response without ERROR-CODE")
        return decode_error_code(attribute.value)

    def _fail(self, reason: str) -> Decision:
        self.phase = Phase.FAILED
        return Decision(Action.GIVE_UP, reason=reason)

    def _close(self, reason: str) -> Decision:
        self.phase = Phase.CLOSED
        self.relayed = []
        return Decision(Action.CLOSED, reason=reason)

    def _challenge(self, message: Message) -> Decision:
        realm, nonce = message.find(REALM), message.find(NONCE)
        if realm is None or nonce is None:
            return self._fail("401 without REALM and NONCE")
        self.realm, self.nonce = realm.value, nonce.value
        self._authenticated = True
        return Decision(Action.RETRY_AUTH, reason="long-term credentials requested")

    def _stale_nonce(self, message: Message) -> Decision:
        nonce = message.find(NONCE)
        self._stale_nonces += 1
        if nonce is None or self._stale_nonces > _STALE_NONCE_TRIES:
            return self._fail("stale nonce loop")
        self.nonce = nonce.value
        return Decision(Action.RETRY_NEW_NONCE, reason="stale nonce")

    def _allocated(self, message: Message, now: float) -> Decision:
        relayed = [
            xor_mapped_address(a.value, message.transaction_id)
            for a in message.attributes
            if a.type == XOR_RELAYED_ADDRESS
        ]
        mapped = message.find(XOR_MAPPED_ADDRESS)
        lifetime = message.find(LIFETIME)
        if not relayed or lifetime is None:
            return self._fail("Allocate success without XOR-RELAYED-ADDRESS or LIFETIME")
        wanted = {FAMILY_IPV6 if ":" in ip else FAMILY_IPV4 for ip, _ in relayed}
        if mapped is not None:
            ip, port = xor_mapped_address(mapped.value, message.transaction_id)
            wanted.add(FAMILY_IPV6 if ":" in ip else FAMILY_IPV4)
            self.mapped = (ip, port)
        if not wanted <= self.families:  # sec. 7.3 para 1: delete, and do not retry here
            self.phase = Phase.ACTIVE
            self.relayed = relayed
            return Decision(Action.DELETE, reason="relayed address family not handled")
        self.relayed = relayed
        self.lifetime = decode_lifetime(lifetime.value)
        self.expires_at = now + self.lifetime
        token = message.find(RESERVATION_TOKEN)
        self.reservation_token = decode_reservation_token(token.value) if token else None
        self.partial_failures = [
            decode_address_error_code(a.value)[:2]
            for a in message.attributes
            if a.type == ADDRESS_ERROR_CODE
        ]
        if any(code == 508 for _, code in self.partial_failures):  # sec. 7.3 para 3
            self.backoff_until = now + 60.0
        self.phase = Phase.ACTIVE
        self._stale_nonces = 0
        return Decision(Action.ACTIVE, reason="allocated")

    def _allocate_error(self, message: Message, now: float) -> Decision:
        code, reason = self._error(message)
        if code == 401:
            if self._authenticated:
                return self._fail("credentials rejected (401 after authenticating)")
            return self._challenge(message)
        if code == 438:
            return self._stale_nonce(message)
        if code == 300:
            alternate = message.find(ALTERNATE_SERVER)
            if alternate is None:
                return self._fail("300 without ALTERNATE-SERVER")
            self.phase = Phase.IDLE
            return Decision(Action.TRY_ALTERNATE, alternate=mapped_address(alternate.value))
        if code == 420:
            unknown = message.find(UNKNOWN_ATTRIBUTES)
            listed = set(decode_unknown_attributes(unknown.value)) if unknown else set()
            if DONT_FRAGMENT in listed:
                self.phase = Phase.IDLE
                return Decision(Action.RETRY_WITHOUT, drop=frozenset({DONT_FRAGMENT}))
            return self._fail("420 for an attribute that is not DONT-FRAGMENT")
        if code == 437:
            self.tuple_tries += 1
            if self.tuple_tries >= _TUPLE_TRIES:
                self.backoff_until = now + 120.0
                self.phase = Phase.FAILED
                return Decision(Action.BACKOFF, wait=120.0, reason="three 5-tuples were in use")
            self.phase = Phase.IDLE
            return Decision(Action.NEW_TUPLE, reason="allocation mismatch")
        if code == 486:
            self.backoff_until = now + 60.0
            self.phase = Phase.FAILED
            return Decision(Action.BACKOFF, wait=60.0, reason="allocation quota reached")
        if code == 508:
            if self._sent_even_port_or_token:
                self.phase = Phase.IDLE
                return Decision(
                    Action.RETRY_WITHOUT,
                    drop=frozenset({EVEN_PORT, RESERVATION_TOKEN}),
                    reason="insufficient capacity for the requested port",
                )
            self.backoff_until = now + 60.0
            self.phase = Phase.FAILED
            return Decision(Action.BACKOFF, wait=60.0, reason="insufficient capacity")
        if code == 440:
            return self._fail("address family not supported: never retried (sec. 7.4)")
        return self._fail(f"Allocate refused with {code} {reason}".strip())
