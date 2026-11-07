# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation turnkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `message.encode_message()` | RFC 8489 sec. 5, sec. 14 | `[ ]` | `tests/test_obligations.py::test_encode_message` (to be written) | M1 |
| `message.decode_message()` | RFC 8489 sec. 5, sec. 14 | `[ ]` | `tests/test_obligations.py::test_decode_message` (to be written) | M1 |
| `allocation.allocate()` | RFC 8656 sec. 7 | `[ ]` | `tests/test_obligations.py::test_allocate` (to be written) | M3 |
| `allocation.refresh()` | RFC 8656 sec. 8 | `[ ]` | `tests/test_obligations.py::test_refresh` (to be written) | M3 |
| `permission.create_permission()` | RFC 8656 sec. 10 | `[ ]` | `tests/test_obligations.py::test_create_permission` (to be written) | M4 |
| `credentials.rest_credentials()` | RFC 7635 | `[ ]` | `tests/test_obligations.py::test_rest_credentials` (to be written) | M3 |
| `ice.gather_candidates()` | RFC 8445 sec. 5.1 | `[ ]` | `tests/test_obligations.py::test_gather_candidates` (to be written) | M5 |
| `ice.schedule_checks()` | RFC 8445 sec. 6.1 | `[ ]` | `tests/test_obligations.py::test_schedule_checks` (to be written) | M5 |
| `sansio.on_binding_response()` | RFC 8445 sec. 7.2, RFC 8863 | `[ ]` | `tests/test_obligations.py::test_on_binding_response` (to be written) | M5 |
| `trickle.encode_end_of_candidates()` | RFC 8838 sec. 13 | `[ ]` | `tests/test_obligations.py::test_encode_end_of_candidates` (to be written) | M5 |

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

- RFC 8489 carries 3 verified errata. 6268 (Technical) corrects the Appendix B.1 test vector: the printed message length counts the 20-byte header, and the vector lacks the PASSWORD-ALGORITHM attribute its SHA-256 key needs, so test against the corrected vector, not the published one. 6290 (Technical) fixes the bit order of the sec. 18.1 bit set; 8434 is a typo.
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
- credentials.rest_credentials takes a username and shared secret, but RFC 7635 obtains an OAuth access token (sec. 4) and defines no such credential: rename the row to the RFC 7635 token, or cite the document that defines the shared-secret scheme
- M2 names the UDP, TCP and TLS transports, but no api row sits on it: add a transport row, or drop the rung

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
