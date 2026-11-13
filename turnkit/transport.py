"""Transaction timing for STUN over UDP, DTLS-over-UDP and TCP or TLS (RFC 8489 sec. 6.2).

Everything here is pure state driven by a clock value the caller passes in; nothing opens a
socket or sleeps, so a test can run a whole 39.5 second transaction in a loop. Framing a
byte stream is :func:`turnkit.message.stream_message_length`.

Reading of RFC 8489 sec. 6.2.1, each point pinned by a test in ``tests/test_transport.py``:

* A request is sent at once, then again after RTO, then after 2*RTO more, and so on, doubling,
  until ``rc`` requests have been sent (default 7). The transaction fails ``rm * RTO`` after
  the last request (default 16). With RTO 0.5 s the sends are at 0, 0.5, 1.5, 3.5, 7.5, 15.5
  and 31.5 s and the failure at 39.5 s, the example in the RFC.
* The initial RTO is at least 500 ms. RFC 6298 sec. 2.4 would round an RTO up to one second;
  sec. 6.2.1 says "SHOULD NOT be rounded up to the nearest second" and allows the exception,
  so the floor here is the initial RTO (``INITIAL_RTO``), not one second. This is a reading,
  since the two texts do not say how they combine.
* Karn: an RTT sample is taken only from a transaction that was never retransmitted.
* The RTO is cached per server IP address and discarded after 10 minutes without a
  transaction there. At most 10 requests are outstanding to one server by default.
* Over TCP and TLS there are no retransmissions: the transaction times out ``ti`` seconds
  after the request was sent (default 39.5 s, sec. 6.2.2) or when the connection fails.

Not here: the sockets, TLS and DTLS handshakes (no DTLS in the standard library), and ICMP
delivery, which a caller reports through :meth:`UdpTransaction.hard_icmp_error`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "DEFAULT_RC",
    "DEFAULT_RM",
    "DEFAULT_TI",
    "INITIAL_RTO",
    "MAX_OUTSTANDING",
    "Failed",
    "OutstandingLimit",
    "RtoCache",
    "RtoEstimator",
    "Send",
    "StreamTransaction",
    "UdpTransaction",
    "Wait",
    "retransmit_offsets",
    "udp_failure_offset",
]

INITIAL_RTO = 0.5  # sec. 6.2.1: SHOULD be at least 500 ms
DEFAULT_RC = 7  # total requests sent
DEFAULT_RM = 16  # multiplier of RTO after the last request
DEFAULT_TI = 39.5  # sec. 6.2.2
MAX_OUTSTANDING = 10  # sec. 6.2: SHOULD limit itself to ten
CACHE_LIFETIME = 600.0  # sec. 6.2.1: stale after 10 minutes
_ALPHA = 1 / 8  # RFC 6298 sec. 2.3
_BETA = 1 / 4
_K = 4
_GRANULARITY = 0.001  # 1 ms accuracy, sec. 6.2.1


def retransmit_offsets(rto: float = INITIAL_RTO, rc: int = DEFAULT_RC) -> tuple[float, ...]:
    """Seconds after the first request at which each of the ``rc`` requests is sent."""
    if rto <= 0 or rc < 1:
        raise ValueError("rto must be positive and rc at least 1")
    offsets = [0.0]
    gap = rto
    for _ in range(rc - 1):
        offsets.append(offsets[-1] + gap)
        gap *= 2
    return tuple(offsets)


def udp_failure_offset(
    rto: float = INITIAL_RTO, rc: int = DEFAULT_RC, rm: int = DEFAULT_RM
) -> float:
    """Seconds after the first request at which a silent transaction is declared failed."""
    return retransmit_offsets(rto, rc)[-1] + rm * rto


@dataclass(frozen=True)
class Send:
    """Transmit the request now; ``attempt`` counts from 1 (the original request)."""

    attempt: int


@dataclass(frozen=True)
class Wait:
    """Nothing to do before the clock reaches ``until``."""

    until: float


@dataclass(frozen=True)
class Failed:
    """The transaction failed; ``reason`` says how (timeout, icmp, connection)."""

    reason: str


class _State(Enum):
    RUNNING = 1
    DONE = 2
    FAILED = 3


class UdpTransaction:
    """One request/response transaction over UDP or DTLS-over-UDP (sec. 6.2.1).

    Call :meth:`poll` with the current time whenever it may be due; it returns what to do.
    The first poll at ``start`` returns ``Send(1)``. Report a matching response with
    :meth:`on_response`, which returns the RTT sample or ``None`` when Karn's rule forbids one.
    """

    def __init__(
        self,
        start: float,
        rto: float = INITIAL_RTO,
        rc: int = DEFAULT_RC,
        rm: int = DEFAULT_RM,
    ) -> None:
        self.start = start
        self.rto = rto
        self._offsets = retransmit_offsets(rto, rc)
        self._deadline = start + udp_failure_offset(rto, rc, rm)
        self._sent: list[float] = []
        self._state = _State.RUNNING

    @property
    def attempts(self) -> int:
        """Requests sent so far."""
        return len(self._sent)

    @property
    def finished(self) -> bool:
        """True once a response arrived or the transaction failed."""
        return self._state is not _State.RUNNING

    def poll(self, now: float) -> Send | Wait | Failed:
        """What to do at ``now``: send (again), wait until a time, or the transaction failed."""
        if self._state is _State.FAILED:
            return Failed("timeout")
        if self._state is _State.DONE:
            return Wait(float("inf"))
        index = len(self._sent)
        if index < len(self._offsets) and now >= self.start + self._offsets[index]:
            self._sent.append(now)
            return Send(index + 1)
        if now >= self._deadline and index == len(self._offsets):
            self._state = _State.FAILED
            return Failed("timeout")
        due = self.start + self._offsets[index] if index < len(self._offsets) else self._deadline
        return Wait(due)

    def on_response(self, now: float) -> float | None:
        """A response arrived: finish, and return the RTT sample unless the request was resent."""
        if self._state is not _State.RUNNING or not self._sent:
            return None
        self._state = _State.DONE
        return now - self._sent[0] if len(self._sent) == 1 else None

    def hard_icmp_error(self) -> Failed:
        """A hard ICMP error [RFC 1122] ends the transaction as failed (sec. 6.2.1)."""
        self._state = _State.FAILED
        return Failed("icmp")


class StreamTransaction:
    """One request over TCP or TLS-over-TCP: no retransmission, only a timeout (sec. 6.2.2)."""

    def __init__(self, start: float, ti: float = DEFAULT_TI) -> None:
        self.start = start
        self.deadline = start + ti
        self._state = _State.RUNNING

    @property
    def finished(self) -> bool:
        """True once a response arrived or the transaction failed."""
        return self._state is not _State.RUNNING

    def poll(self, now: float) -> Wait | Failed:
        """Wait until the deadline, then fail."""
        if self._state is _State.FAILED or (self._state is _State.RUNNING and now >= self.deadline):
            self._state = _State.FAILED
            return Failed("timeout")
        return Wait(float("inf") if self._state is _State.DONE else self.deadline)

    def on_response(self, now: float) -> None:
        """A response arrived in time; a late one (after the deadline) is ignored."""
        if self._state is _State.RUNNING and now < self.deadline:
            self._state = _State.DONE

    def connection_failed(self) -> Failed:
        """The connection could not open or was reset: the transaction failed (sec. 6.2.2)."""
        self._state = _State.FAILED
        return Failed("connection")


class RtoEstimator:
    """SRTT, RTTVAR and RTO as RFC 6298 sec. 2 defines them, with the sec. 6.2.1 floor."""

    def __init__(self, initial: float = INITIAL_RTO, minimum: float = INITIAL_RTO) -> None:
        self.minimum = minimum
        self.srtt: float | None = None
        self.rttvar: float = 0.0
        self.rto = max(initial, minimum)

    def sample(self, rtt: float) -> float:
        """Fold in one RTT measurement; return the new RTO."""
        if rtt < 0:
            raise ValueError("an RTT cannot be negative")
        if self.srtt is None:  # rule 2.2
            self.srtt = rtt
            self.rttvar = rtt / 2
        else:  # rule 2.3: RTTVAR first, with the old SRTT
            self.rttvar = (1 - _BETA) * self.rttvar + _BETA * abs(self.srtt - rtt)
            self.srtt = (1 - _ALPHA) * self.srtt + _ALPHA * rtt
        self.rto = max(self.srtt + max(_GRANULARITY, _K * self.rttvar), self.minimum)
        return self.rto


class RtoCache:
    """The RTO to start the next transaction with, per server IP address (sec. 6.2.1)."""

    def __init__(self, initial: float = INITIAL_RTO) -> None:
        self.initial = initial
        self._entries: dict[str, tuple[RtoEstimator, float]] = {}

    def rto(self, server: str, now: float) -> float:
        """The cached RTO, or the initial one when there is none or it is stale."""
        entry = self._entries.get(server)
        if entry is None or now - entry[1] > CACHE_LIFETIME:
            self._entries.pop(server, None)
            return self.initial
        return entry[0].rto

    def record(self, server: str, rtt: float | None, now: float) -> None:
        """Note a finished transaction; ``rtt`` is ``None`` when Karn's rule gave no sample."""
        entry = self._entries.get(server)
        if entry is None or now - entry[1] > CACHE_LIFETIME:
            entry = (RtoEstimator(self.initial), now)
        if rtt is not None:
            entry[0].sample(rtt)
        self._entries[server] = (entry[0], now)


class OutstandingLimit:
    """Counts requests in flight to one server; ``try_start`` refuses past the limit."""

    def __init__(self, limit: int = MAX_OUTSTANDING) -> None:
        if limit < 1:
            raise ValueError("the limit is at least 1")
        self.limit = limit
        self.outstanding = 0

    def try_start(self) -> bool:
        """Reserve a slot; False when ``limit`` requests are already outstanding."""
        if self.outstanding >= self.limit:
            return False
        self.outstanding += 1
        return True

    def finish(self) -> None:
        """Release a slot when a transaction ends."""
        if self.outstanding == 0:
            raise ValueError("no transaction is outstanding")
        self.outstanding -= 1
