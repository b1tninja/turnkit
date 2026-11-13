"""RFC 8489 sec. 6.2 transaction timing, driven by a virtual clock."""

from __future__ import annotations

import pytest

from turnkit.transport import (
    Failed,
    OutstandingLimit,
    RtoCache,
    RtoEstimator,
    Send,
    StreamTransaction,
    UdpTransaction,
    Wait,
    retransmit_offsets,
    udp_failure_offset,
)


def run(transaction, until=100.0, step=0.001):
    """Poll a transaction on a 1 ms clock; return the (time, action) sends and the failure."""
    sends, failed, tick = [], None, 0
    while tick * step <= until and failed is None:
        now = tick * step
        action = transaction.poll(now)
        if isinstance(action, Send):
            sends.append((round(now, 3), action.attempt))
        elif isinstance(action, Failed):
            failed = round(now, 3)
        tick += 1
    return sends, failed


def test_rto_schedule():
    # the worked example of RFC 8489 sec. 6.2.1: RTO 500 ms, Rc 7, Rm 16
    assert retransmit_offsets(0.5, 7) == (0.0, 0.5, 1.5, 3.5, 7.5, 15.5, 31.5)
    assert udp_failure_offset(0.5, 7, 16) == 39.5
    sends, failed = run(UdpTransaction(0.0))
    assert sends == [(0.0, 1), (0.5, 2), (1.5, 3), (3.5, 4), (7.5, 5), (15.5, 6), (31.5, 7)]
    assert failed == 39.5


def test_schedule_scales_with_rto_and_a_late_start():
    sends, failed = run(UdpTransaction(10.0, rto=1.0, rc=3, rm=4), until=30.0)
    assert [t for t, _ in sends] == [10.0, 11.0, 13.0]
    assert failed == 17.0  # last send at 13 plus 4 * RTO


def test_a_response_stops_retransmission_and_karn_withholds_the_sample():
    clean = UdpTransaction(0.0)
    assert clean.poll(0.0) == Send(1)
    assert clean.on_response(0.08) == pytest.approx(0.08)
    assert clean.finished
    assert isinstance(clean.poll(5.0), Wait)  # nothing more to send
    resent = UdpTransaction(0.0)
    resent.poll(0.0)
    assert resent.poll(0.5) == Send(2)
    assert resent.on_response(0.55) is None  # Karn: ambiguous, no RTT sample
    assert resent.poll(2.0) == Wait(float("inf"))


def test_poll_before_a_deadline_says_when_to_come_back():
    transaction = UdpTransaction(0.0)
    assert transaction.poll(0.0) == Send(1)
    assert transaction.poll(0.2) == Wait(0.5)
    assert transaction.poll(0.5) == Send(2)
    assert transaction.poll(1.5) == Send(3)
    for at in (3.5, 7.5, 15.5, 31.5):
        assert isinstance(transaction.poll(at), Send)
    assert transaction.poll(39.4) == Wait(39.5)  # all seven sent: wait Rm * RTO
    assert transaction.poll(39.5) == Failed("timeout")


def test_hard_icmp_error_fails_at_once():
    transaction = UdpTransaction(0.0)
    transaction.poll(0.0)
    assert transaction.hard_icmp_error() == Failed("icmp")
    assert transaction.poll(0.1) == Failed("timeout")  # stays failed
    assert transaction.finished


def test_stream_transaction_times_out_without_retransmission():
    transaction = StreamTransaction(5.0)
    assert transaction.poll(5.0) == Wait(44.5)  # 39.5 s later, sec. 6.2.2
    assert transaction.poll(44.4) == Wait(44.5)
    assert transaction.poll(44.5) == Failed("timeout")
    ok = StreamTransaction(0.0)
    ok.on_response(10.0)
    assert ok.finished
    assert ok.poll(50.0) == Wait(float("inf"))
    late = StreamTransaction(0.0)
    late.on_response(40.0)  # after the deadline: ignored
    assert late.poll(40.0) == Failed("timeout")
    assert StreamTransaction(0.0).connection_failed() == Failed("connection")


def test_rto_estimator_follows_rfc_6298():
    estimator = RtoEstimator()
    assert estimator.rto == 0.5
    # rule 2.2: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR, floored at 500 ms
    assert estimator.sample(0.2) == pytest.approx(0.2 + 4 * 0.1)
    assert estimator.srtt == pytest.approx(0.2)
    assert estimator.rttvar == pytest.approx(0.1)
    # rule 2.3: RTTVAR uses the old SRTT, then SRTT moves by alpha = 1/8
    estimator.sample(0.4)
    assert estimator.rttvar == pytest.approx(0.75 * 0.1 + 0.25 * 0.2)
    assert estimator.srtt == pytest.approx(0.875 * 0.2 + 0.125 * 0.4)
    # the floor: a fast path never gives an RTO under 500 ms
    fast = RtoEstimator()
    for _ in range(50):
        fast.sample(0.001)
    assert fast.rto == 0.5
    with pytest.raises(ValueError, match="negative"):
        estimator.sample(-1)


def test_rto_cache_is_per_server_and_goes_stale_after_ten_minutes():
    cache = RtoCache()
    assert cache.rto("192.0.2.1", 0.0) == 0.5
    cache.record("192.0.2.1", 0.4, 100.0)
    assert cache.rto("192.0.2.1", 200.0) == pytest.approx(0.4 + 4 * 0.2)
    assert cache.rto("192.0.2.2", 200.0) == 0.5  # another server
    assert cache.rto("192.0.2.1", 100.0 + 601.0) == 0.5  # stale: discarded
    cache.record("192.0.2.1", None, 1000.0)  # Karn: no sample, entry still created
    assert cache.rto("192.0.2.1", 1001.0) == 0.5


def test_ten_outstanding_transactions_per_server():
    limit = OutstandingLimit()
    assert all(limit.try_start() for _ in range(10))
    assert not limit.try_start()
    limit.finish()
    assert limit.try_start()
    for _ in range(10):
        limit.finish()
    with pytest.raises(ValueError, match="no transaction"):
        limit.finish()
