"""RFC 8656 sec. 7 and sec. 8: the allocation lifecycle as pure state."""

from __future__ import annotations

import pytest

from turnkit import attributes as a
from turnkit import turn_attributes as t
from turnkit.lifecycle import (
    DEFAULT_LIFETIME,
    Action,
    AllocationClient,
    Phase,
    allocate_attributes,
    delete_attributes,
    desired_lifetime,
    refresh_attributes,
)
from turnkit.message import Attribute, Message, StunClass, make_message_type

TID = bytes(range(12))


def response(method, klass, *attributes):
    return Message(make_message_type(method, klass), TID, tuple(attributes))


def error(method, code, *extra):
    return response(method, StunClass.ERROR, a.encode_error_code(code), *extra)


def success(*, relayed=(("192.0.2.15", 50000),), lifetime=600, mapped=("203.0.113.7", 4000), **kw):
    attributes = [t.encode_xor_relayed_address(ip, port, TID) for ip, port in relayed]
    attributes.append(t.encode_lifetime(lifetime))
    if mapped:
        attributes.append(a.encode_xor_mapped_address(*mapped, TID))
    if kw.get("token"):
        attributes.append(t.encode_reservation_token(kw["token"]))
    attributes.extend(kw.get("extra", ()))
    return response(t.ALLOCATE, StunClass.SUCCESS, *attributes)


def started(**kwargs):
    client = AllocationClient(**kwargs)
    client.start_allocate(allocate_attributes(), 0.0)
    return client


def types(attributes):
    return [x.type for x in attributes]


def test_allocate_request_attributes_and_the_client_musts_of_section_7_1():
    assert types(allocate_attributes()) == [t.REQUESTED_TRANSPORT]
    full = allocate_attributes(
        family=a.FAMILY_IPV6, lifetime=1200, dont_fragment=True, even_port=True
    )
    assert types(full) == [
        t.REQUESTED_TRANSPORT,
        t.REQUESTED_ADDRESS_FAMILY,
        t.LIFETIME,
        t.DONT_FRAGMENT,
        t.EVEN_PORT,
    ]
    dual = allocate_attributes(additional_ipv6=True)
    assert types(dual) == [t.REQUESTED_TRANSPORT, t.ADDITIONAL_ADDRESS_FAMILY]
    token = bytes(8)
    assert t.RESERVATION_TOKEN in types(allocate_attributes(reservation_token=token))
    for bad in (
        {"family": a.FAMILY_IPV4, "additional_ipv6": True},
        {"reservation_token": token, "family": a.FAMILY_IPV4},
        {"reservation_token": token, "additional_ipv6": True},
        {"reservation_token": token, "even_port": False},
        {"additional_ipv6": True, "even_port": True},
    ):
        with pytest.raises(ValueError, match=r"beside|together"):
            allocate_attributes(**bad)
    # EVEN-PORT with R=0 is allowed beside the dual request
    assert allocate_attributes(additional_ipv6=True, even_port=False)


def test_refresh_and_delete_attributes():
    assert refresh_attributes() == ()
    assert refresh_attributes(lifetime=900)[0] == t.encode_lifetime(900)
    assert delete_attributes() == (t.encode_lifetime(0),)
    assert types(delete_attributes(family=a.FAMILY_IPV6)) == [
        t.LIFETIME,
        t.REQUESTED_ADDRESS_FAMILY,
    ]


def test_desired_lifetime_arithmetic():
    assert desired_lifetime(None) == 600
    assert desired_lifetime(0) == 0  # a Refresh deletes
    assert desired_lifetime(30) == 600  # below the default: the default
    assert desired_lifetime(1200) == 1200
    assert desired_lifetime(99999) == 3600  # capped at the server maximum
    assert desired_lifetime(1200, maximum=900) == 900
    assert desired_lifetime(300, default=300, maximum=300) == 300


def test_allocate_success_then_refresh_then_delete():
    client = started()
    assert client.phase is Phase.ALLOCATING
    decision = client.on_allocate_response(success(lifetime=600, token=bytes(range(8))), 10.0)
    assert decision.action is Action.ACTIVE
    assert client.phase is Phase.ACTIVE
    assert client.relayed == [("192.0.2.15", 50000)]
    assert client.mapped == ("203.0.113.7", 4000)
    assert client.expires_at == 610.0
    assert client.reservation_token == bytes(range(8))
    # sec. 8: refresh roughly one minute before expiry
    assert not client.refresh_due(500.0)
    assert client.refresh_due(550.0)
    assert not client.has_expired(609.0)
    assert client.has_expired(610.0)
    refreshed = response(t.REFRESH, StunClass.SUCCESS, t.encode_lifetime(1800))
    assert client.on_refresh_response(refreshed, 560.0).action is Action.ACTIVE
    assert client.lifetime == 1800
    assert client.expires_at == 2360.0  # the lifetime the server returned, not the one asked
    assert delete_attributes() == client.start_delete()
    assert client.phase is Phase.DELETING
    gone = response(t.REFRESH, StunClass.SUCCESS, t.encode_lifetime(0))
    assert client.on_refresh_response(gone, 600.0).action is Action.CLOSED
    assert client.phase is Phase.CLOSED
    assert client.relayed == []


def test_allocate_401_then_438():
    client = started()
    challenge = error(
        t.ALLOCATE, 401, Attribute(a.REALM, b"example.org"), Attribute(a.NONCE, b"nonce-1")
    )
    decision = client.on_allocate_response(challenge, 0.0)
    assert decision.action is Action.RETRY_AUTH
    assert (client.realm, client.nonce) == (b"example.org", b"nonce-1")
    # the authenticated retry meets a stale nonce: retry again with the new one
    stale = error(t.ALLOCATE, 438, Attribute(a.NONCE, b"nonce-2"))
    decision = client.on_allocate_response(stale, 0.1)
    assert decision.action is Action.RETRY_NEW_NONCE
    assert client.nonce == b"nonce-2"
    assert client.on_allocate_response(success(), 0.2).action is Action.ACTIVE
    # a 401 after authenticating means the credentials are wrong
    again = started()
    again.on_allocate_response(challenge, 0.0)
    rejected = again.on_allocate_response(challenge, 0.1)
    assert rejected.action is Action.GIVE_UP
    assert again.phase is Phase.FAILED
    # a 401 with no realm and nonce cannot be answered
    assert started().on_allocate_response(error(t.ALLOCATE, 401), 0).action is Action.GIVE_UP


def test_stale_nonce_loop_is_bounded():
    client = started()
    stale = error(t.ALLOCATE, 438, Attribute(a.NONCE, b"n"))
    actions = [client.on_allocate_response(stale, 0.0).action for _ in range(4)]
    assert actions == [Action.RETRY_NEW_NONCE] * 3 + [Action.GIVE_UP]


def test_error_responses_follow_section_7_4():
    # 437: another 5-tuple, three tries, then two minutes
    client = AllocationClient()
    for expected in (Action.NEW_TUPLE, Action.NEW_TUPLE, Action.BACKOFF):
        client.start_allocate(allocate_attributes(), 0.0)
        decision = client.on_allocate_response(error(t.ALLOCATE, 437), 5.0)
        assert decision.action is expected
    assert decision.wait == 120.0
    with pytest.raises(ValueError, match=r"must not allocate before 125\.0"):
        client.start_allocate(allocate_attributes(), 100.0)
    # 486 and 508 wait one minute
    for code in (486, 508):
        client = started()
        decision = client.on_allocate_response(error(t.ALLOCATE, code), 0.0)
        assert (decision.action, decision.wait) == (Action.BACKOFF, 60.0)
    # 508 for a request that used EVEN-PORT or a token: retry at once without them
    client = AllocationClient()
    client.start_allocate(allocate_attributes(even_port=True), 0.0)
    decision = client.on_allocate_response(error(t.ALLOCATE, 508), 0.0)
    assert decision.action is Action.RETRY_WITHOUT
    assert decision.drop == {t.EVEN_PORT, t.RESERVATION_TOKEN}
    # 440 is never retried; 400, 403, 441 and 442 end the attempt
    for code in (440, 400, 403, 441, 442):
        client = started()
        assert client.on_allocate_response(error(t.ALLOCATE, code), 0.0).action is Action.GIVE_UP
        assert client.phase is Phase.FAILED


def test_420_for_dont_fragment_retries_without_it():
    client = AllocationClient()
    client.start_allocate(allocate_attributes(dont_fragment=True), 0.0)
    unknown = a.encode_unknown_attributes([t.DONT_FRAGMENT])
    decision = client.on_allocate_response(error(t.ALLOCATE, 420, unknown), 0.0)
    assert (decision.action, decision.drop) == (Action.RETRY_WITHOUT, {t.DONT_FRAGMENT})
    other = a.encode_unknown_attributes([0x7777])
    assert started().on_allocate_response(error(t.ALLOCATE, 420, other), 0).action is Action.GIVE_UP


def test_300_goes_to_the_alternate_server():
    client = started()
    alternate = a.encode_mapped_address("198.51.100.9", 3478, a.ALTERNATE_SERVER)
    decision = client.on_allocate_response(error(t.ALLOCATE, 300, alternate), 0.0)
    assert decision.action is Action.TRY_ALTERNATE
    assert decision.alternate == ("198.51.100.9", 3478)
    assert client.phase is Phase.IDLE
    assert started().on_allocate_response(error(t.ALLOCATE, 300), 0).action is Action.GIVE_UP


def test_unhandled_family_in_the_success_means_delete():
    client = started(families=frozenset({a.FAMILY_IPV4}))
    decision = client.on_allocate_response(success(relayed=(("2001:db8::1", 49152),)), 0.0)
    assert decision.action is Action.DELETE
    assert client.start_delete() == delete_attributes()  # the caller now deletes it
    # a dual allocation of two handled families is accepted whole
    dual = started()
    two = success(relayed=(("192.0.2.15", 50000), ("2001:db8::1", 49152)))
    assert dual.on_allocate_response(two, 0.0).action is Action.ACTIVE
    assert len(dual.relayed) == 2


def test_partial_dual_allocation_reports_address_error_code():
    client = started()
    partial = t.encode_address_error_code(a.FAMILY_IPV6, 508, "no capacity")
    message = success(extra=(partial,))
    assert client.on_allocate_response(message, 100.0).action is Action.ACTIVE
    assert client.partial_failures == [(a.FAMILY_IPV6, 508)]
    assert client.backoff_until == 160.0  # sec. 7.3: wait a minute before asking for that family


def test_refresh_errors_follow_section_8_3():
    def active():
        client = started()
        client.on_allocate_response(success(), 0.0)
        return client

    client = active()
    assert client.on_refresh_response(error(t.REFRESH, 437), 1.0).action is Action.CLOSED
    assert client.phase is Phase.CLOSED
    # 437 to a delete is success
    client = active()
    client.start_delete()
    decision = client.on_refresh_response(error(t.REFRESH, 437), 1.0)
    assert decision.action is Action.CLOSED
    assert "delete" in decision.reason
    # 438 reattempts with the new nonce
    client = active()
    stale = error(t.REFRESH, 438, Attribute(a.NONCE, b"fresh"))
    assert client.on_refresh_response(stale, 1.0).action is Action.RETRY_NEW_NONCE
    assert client.nonce == b"fresh"
    assert active().on_refresh_response(error(t.REFRESH, 403), 1.0).action is Action.GIVE_UP


def test_timeouts_and_misuse_are_loud():
    assert started().on_timeout().action is Action.GIVE_UP
    client = started()
    with pytest.raises(ValueError, match="not a response"):
        client.on_allocate_response(response(t.REFRESH, StunClass.SUCCESS), 0.0)
    with pytest.raises(ValueError, match="unexpected response"):
        client.on_refresh_response(response(t.REFRESH, StunClass.SUCCESS), 0.0)
    with pytest.raises(ValueError, match="without ERROR-CODE"):
        client.on_allocate_response(response(t.ALLOCATE, StunClass.ERROR), 0.0)
    with pytest.raises(ValueError, match="no active allocation"):
        AllocationClient().start_delete()
    done = started()
    done.on_allocate_response(success(), 0.0)
    with pytest.raises(ValueError, match="exists on this 5-tuple"):
        done.start_allocate(allocate_attributes(), 1.0)
    # a success without the attributes the RFC lists is a failure, not a guess
    empty = response(t.ALLOCATE, StunClass.SUCCESS, t.encode_lifetime(600))
    assert started().on_allocate_response(empty, 0.0).action is Action.GIVE_UP
    assert DEFAULT_LIFETIME == 600
