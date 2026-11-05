# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation turnkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `message.encode_message()` | RFC 8489 | `[ ]` | `tests/test_obligations.py::encode_message` |
| `message.decode_message()` | RFC 8489 | `[ ]` | `tests/test_obligations.py::decode_message` |
| `allocation.allocate()` | RFC 8656 | `[ ]` | `tests/test_obligations.py::allocate` |
| `allocation.refresh()` | RFC 8656 | `[ ]` | `tests/test_obligations.py::refresh` |
| `permission.create_permission()` | RFC 8656 | `[ ]` | `tests/test_obligations.py::create_permission` |
| `credentials.rest_credentials()` | RFC 7635 | `[ ]` | `tests/test_obligations.py::rest_credentials` |
| `ice.gather_candidates()` | RFC 8445 | `[ ]` | `tests/test_obligations.py::gather_candidates` |
| `ice.schedule_checks()` | RFC 8445 | `[ ]` | `tests/test_obligations.py::schedule_checks` |
| `sansio.on_binding_response()` | RFC 8445, RFC 8863 | `[ ]` | `tests/test_obligations.py::on_binding_response` |
| `trickle.encode_end_of_candidates()` | RFC 8838 | `[ ]` | `tests/test_obligations.py::encode_end_of_candidates` |

## 2. Milestones

- M1 STUN codec, integrity and fingerprint against published vectors
- M2 transports: UDP, TCP, TLS, with framing and timeout policy
- M3 TURN allocation lifecycle including 401 nonce replay and refresh
- M4 permissions and channels, then RFC 8016 mobility
- M5 sans-IO ICE agent with RFC 8863 failure timing, then trickle
- M6 publication: 0.1.0 with a relay interoperability trace

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 8489 carries 3 verified errata.
- RFC 8445 is updated by RFC 8863, and RFC 8656 is the successor to RFC 5766 and RFC 6156: do not copy recipes from either predecessor.
- RFC 8838 and RFC 8863 report no errata as of 2026-10-29.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a WebRTC stack or any SDP handling | `[no]` | a named document requires it |
| DTLS-SRTP or media of any kind: the relayed path is opaque here | `[no]` | a named document requires it |
| a TURN server, which is an operational product rather than a client library | `[no]` | a named document requires it |

## 5. Open questions

- does the ICE agent need to be wire compatible with aioice for a shared test harness

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
