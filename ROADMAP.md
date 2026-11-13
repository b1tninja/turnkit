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
| `message.decode_message()` | RFC 8489 sec. 5, sec. 14; RFC 5769 sec. 2.1 to 2.4 | `[ok]` | `tests/test_message.py::test_rfc5769_sample_request` | M1 |
| `message.encode_message()` (optionally signs: MESSAGE-INTEGRITY or -SHA256, then FINGERPRINT last) | RFC 8489 sec. 5, sec. 14, sec. 14.5 to 14.7 | `[ok]` | `tests/test_integrity.py::test_encode_signs_and_verifies_both_algorithms` | M1 |
| `message.make_message_type()` (the class and method bit interleave) | RFC 8489 sec. 5 Figure 3 | `[ok]` | `tests/test_message.py::test_type_bit_interleave` | M1 |
| `message.looks_like_stun()` (cheap demultiplexing test for srtpkit and DTLS-SRTP) | RFC 8489 sec. 5 | `[ok]` | `tests/test_message.py::test_looks_like_stun_demux` | M1 |
| `message.stream_message_length()` (length from the first 20 octets, for a TCP reader) | RFC 8489 sec. 5 | `[ok]` | `tests/test_message.py::test_stream_message_length_from_the_header_alone` | M1 |
| `attributes.xor_mapped_address()` (IPv4 masks with the cookie, IPv6 with cookie and transaction ID) | RFC 8489 sec. 14.2; RFC 5769 sec. 2.2, 2.3 | `[ok]` | `tests/test_message.py::test_ipv6_xor_mapped_address_roundtrip` | M1 |
| `attributes.decode_error_code()` (ERROR-CODE, class 3 to 6) | RFC 8489 sec. 14.8 | `[ok]` | `tests/test_turn_attributes.py::test_error_code_attribute` | M1 |
| `attributes.decode_password_algorithms()` (PASSWORD-ALGORITHM and -S lists) | RFC 8489 sec. 14.11, sec. 14.12 | `[ok]` | `tests/test_turn_attributes.py::test_unknown_attributes_and_password_algorithms` | M1 |
| `integrity.message_integrity_value()` (HMAC-SHA1, length field rewritten) | RFC 8489 sec. 14.5; RFC 5769 sec. 2.1 to 2.3 | `[ok]` | `tests/test_integrity.py::test_rfc5769_hmac_sha1` | M1 |
| `integrity.fingerprint_value()` (CRC-32 XOR 0x5354554e, last attribute) | RFC 8489 sec. 14.7; RFC 5769 sec. 2.1 to 2.3 | `[ok]` | `tests/test_integrity.py::test_rfc5769_fingerprint` | M1 |
| `integrity.check_message_integrity()` (SHA-1 and SHA-256, 16 to 32 octets) | RFC 8489 sec. 14.5, sec. 14.6, sec. 9 para 3 | `[ok]` | `tests/test_integrity.py::test_verify_rejects_one_bit_flip_in_every_byte_before_integrity` | M1 |
| `credentials.short_term_key()` | RFC 8489 sec. 9.1.1 | `[ok]` | `tests/test_integrity.py::test_rfc5769_hmac_sha1` | M1 |
| `credentials.long_term_key()` (MD5 and SHA-256, on prepared strings) | RFC 8489 sec. 9.2.2, sec. 18.5.1; RFC 5769 sec. 2.4 | `[ok]` | `tests/test_integrity.py::test_rfc5769_long_term_vector_with_the_prepared_password` | M1 |
| `credentials.userhash()` | RFC 8489 sec. 14.4; appendix B.1 | `[ok]` | `tests/test_integrity.py::test_rfc8489_b1_userhash` | M1 |
| `credentials.opaque-string` (`credentials.opaque_string` is `precis.opaque_string`; non-ASCII credentials are prepared, an unallowed code point raises `PrecisError`) | RFC 8265, RFC 8489 sec. 9.2.2 | `[ok]` | `tests/test_integrity.py::test_opaque_string_vectors` | M3 |
| `precis.opaque_string()` (RFC 8265 sec. 4.2: no width mapping, non-ASCII Zs to SPACE, no case mapping, NFC, FreeformClass check; compare by octets) | RFC 8265 sec. 4.2, RFC 8264 sec. 4.3 | `[ok]` | `tests/test_precis.py::test_opaque_string_vectors` | M3 |
| `precis.derived_property()` (generated from the IANA Unicode 6.3.0 registry, 1502 records, source sha256 recorded in `turnkit/_precis_table.py`; regenerate with `tools/gen_precis_table.py`) | RFC 8264 sec. 8, sec. 9; IANA precis-tables-6.3.0 | `[ok]` | `tests/test_precis.py::test_table_covers_every_code_point_once_and_carries_provenance` | M3 |
| `precis.unicode-version` (the registry only carries Unicode 6.3.0, so a code point assigned later is UNASSIGNED and refused, emoji from Unicode 10 on for one; the derived property could be computed from the interpreter's Unicode database instead, which would let a key-derivation input change with the Python version; built as the opt-in `opaque_string(..., unicode_database=True)` and `precis.derived_property_from_database()`, the default stays the registry; the Default_Ignorable_Code_Point members that are not Cf are a hand list, checked against the registry for every code point Unicode 6.3.0 assigned but not yet against DerivedCoreProperties.txt, see `precis.ucd-crosscheck`) | RFC 8264 sec. 4.3.4, sec. 8; RFC 5892 sec. 2 | `[ok]` | `tests/test_precis.py::test_unicode_database_is_an_opt_in_for_later_code_points` | M3 |
| `precis.ucd-crosscheck` (check the hand-listed Default_Ignorable_Code_Point members and the Hangul jamo ranges of `derived_property_from_database` against DerivedCoreProperties.txt and HangulSyllableType.txt of the interpreter's Unicode version; needs a download from unicode.org into a cache, not on the approved list) | RFC 8264 sec. 9.13 | `[ ]` | `tests/test_precis.py::test_database_mode_agrees_with_the_registry` | M3 |
| `precis.contextual-rules` (RFC 5892 appendix A per occurrence, erratum 3312; scripts read from character names because the standard library has no Script property; the ZWNJ joining-type pattern is not evaluated, so U+200C is accepted only after a virama) | RFC 5892 appendix A, RFC 8264 sec. 4.3.2 | `[part]` | `tests/test_precis.py::test_contextual_rules_are_evaluated_per_occurrence` | M3 |
| `integrity.sha256-vector` (the printed RFC 8489 appendix B.1 vector is reproducible only with the erroneous length 0x9c, which pins erratum 6268; no corrected vector exists to run) | RFC 8489 appendix B.1, erratum 6268 | `[part]` | `tests/test_integrity.py::test_rfc8489_b1_printed_vector_only_matches_the_erroneous_length` | M1 |
| `turn_attributes.encode_requested_transport()` (and the other Table 5 attributes: CHANNEL-NUMBER, LIFETIME, XOR-PEER-ADDRESS, DATA, XOR-RELAYED-ADDRESS, REQUESTED-ADDRESS-FAMILY, EVEN-PORT, DONT-FRAGMENT, RESERVATION-TOKEN, ADDITIONAL-ADDRESS-FAMILY, ADDRESS-ERROR-CODE, ICMP) | RFC 8656 sec. 18 | `[ok]` | `tests/test_turn_attributes.py::test_allocate_request_roundtrip_with_turn_attributes` | M3 |
| `turn_attributes.decode_icmp()` (8-bit type and code, erratum 8901 reading, reported not verified) | RFC 8656 sec. 18.13, erratum 8901 | `[ok]` | `tests/test_turn_attributes.py::test_icmp_fields_are_8_bits_each_per_erratum_8901` | M4 |
| `turn_attributes.decode_channel_data()` (padding over TCP, reserved range 0x5000 to 0xFFFF discarded) | RFC 8656 sec. 12.4 to 12.6 | `[ok]` | `tests/test_turn_attributes.py::test_channel_data_udp_and_stream_padding` | M4 |
| `turn_attributes.error-codes` (403, 437, 440, 441, 442, 443, 486, 508 are carried by `attributes.encode_error_code`; the client handling of each is in `lifecycle.AllocationClient`; no named constants yet) | RFC 8656 sec. 19 | `[part]` | `tests/test_turn_attributes.py::test_address_error_code_layout` | M3 |
| `allocation.allocate()` (the async function that sends and receives; still a loud stub, the decisions it needs are in `lifecycle`) | RFC 8656 sec. 7 | `[ ]` | `tests/test_obligations.py::test_allocate` (to be written) | M3 |
| `allocation.refresh()` (the async function; still a loud stub) | RFC 8656 sec. 8 | `[ ]` | `tests/test_obligations.py::test_refresh` (to be written) | M3 |
| `lifecycle.allocate_attributes()` (Allocate request attributes, refusing the sec. 7.1 combinations; `refresh_attributes()` and `delete_attributes()` for sec. 8.1) | RFC 8656 sec. 7.1, sec. 8.1 | `[ok]` | `tests/test_lifecycle.py::test_allocate_request_attributes_and_the_client_musts_of_section_7_1` | M3 |
| `lifecycle.desired_lifetime()` (the sec. 7.2 and sec. 8.2 arithmetic: default 600 s, maximum 3600 s, zero deletes) | RFC 8656 sec. 7.2, sec. 8.2 | `[ok]` | `tests/test_lifecycle.py::test_desired_lifetime_arithmetic` | M3 |
| `lifecycle.client-state` (`AllocationClient`: allocate, refresh 1 minute before expiry, delete, 437 as success on delete; pure state, no I/O) | RFC 8656 sec. 7.3, sec. 8.3 | `[ok]` | `tests/test_lifecycle.py::test_allocate_success_then_refresh_then_delete` | M3 |
| `lifecycle.client-errors` (sec. 7.4: 300, 420, 437 three tries then 2 minutes, 438, 440, 486, 508 and the 1-minute waits, 401 once) | RFC 8656 sec. 7.4 | `[ok]` | `tests/test_lifecycle.py::test_error_responses_follow_section_7_4` | M3 |
| `lifecycle.dual-allocation` (two XOR-RELAYED-ADDRESS, ADDRESS-ERROR-CODE partial failure, unhandled family deleted at once; the server side of sec. 7.2 is not built) | RFC 8656 sec. 7.3 | `[part]` | `tests/test_lifecycle.py::test_partial_dual_allocation_reports_address_error_code` | M3 |
| `lifecycle.reservation-hold` (EVEN-PORT R=1 token: the client keeps the token; nothing tracks the server's 30 s hold or uses the token in a second allocation) | RFC 8656 sec. 7.2 | `[ ]` | `tests/test_lifecycle.py::test_reservation_token_second_allocation` (to be written) | M3 |
| `permission.create_permission()` | RFC 8656 sec. 10 | `[ ]` | `tests/test_obligations.py::test_create_permission` (to be written) | M4 |
| `credentials.rest-credentials` (the timestamped-username, HMAC-password TURN REST scheme; RFC 7635 does not define it, it defines OAuth 2.0 access tokens for STUN, so the row cited a document that says something else; no RFC defines the scheme and the draft that does is not in rfclib) | - | `[no]` | decision recorded in section 5 | - |
| `credentials.oauth-access-token` (RFC 7635 third-party authorization: access token, mac_key as the HMAC key; sections 4 to 6 and the 4 errata on file are unread) | RFC 7635 | `[ ]` | `tests/test_integrity.py::test_rfc7635_token_key` (to be written) | M3 |
| `transport.udp-tcp-tls` (sec. 6.2 read 2026-11-13: pure transaction timing is built, `UdpTransaction` with the 0, 0.5, 1.5, 3.5, 7.5, 15.5, 31.5 s schedule and failure at 39.5 s, Karn, `RtoEstimator`, 10-minute `RtoCache`, 10-transaction `OutstandingLimit`, `StreamTransaction` with Ti 39.5 s; no sockets, no TLS client, no DTLS) | RFC 8489 sec. 6.2, RFC 6298 sec. 2 | `[part]` | `tests/test_transport.py::test_rto_schedule` | M2 |
| `transport.rto-floor` (RFC 6298 sec. 2.4 rounds RTO up to 1 s, RFC 8489 sec. 6.2.1 says not to round to the second; the floor is read as the 500 ms initial RTO, an interpretation) | RFC 8489 sec. 6.2.1, RFC 6298 sec. 2.4 | `[ok]` | `tests/test_transport.py::test_rto_estimator_follows_rfc_6298` | M2 |
| `lifecycle.auth-replay` (the decision to replay an Allocate with realm and nonce after 401 and with the new nonce after 438; computing the long-term MESSAGE-INTEGRITY for the replay is `integrity` plus `credentials`; RFC 8489 sec. 9.2.5 itself is unread) | RFC 8656 sec. 7.4, RFC 8489 sec. 9.2.5 | `[part]` | `tests/test_lifecycle.py::test_allocate_401_then_438` | M3 |
| `permission.channel-bind` (ChannelBind request, binding lifetime) and `mobility` (MOBILITY-TICKET) | RFC 8656 sec. 12, RFC 8016 | `[ ]` | `tests/test_permission.py::test_channel_bind` (to be written) | M4 |
| `ice.candidate_priority()` (and `pair_priority()`) | RFC 8445 sec. 5.1.2, sec. 6.1.2.3 | `[ ]` | `tests/test_ice_priority.py::test_priority_formula` (to be written) | M5 |
| `trickle.generate-end-of-candidates` (rename of `trickle.encode_end_of_candidates()`: RFC 8838 sec. 13 says when to generate it, sec. 14 how to receive it, and the encoding belongs to the signalling protocol, not to this library) | RFC 8838 sec. 13, sec. 14 | `[ ]` | `tests/test_trickle.py::test_end_of_candidates` (to be written) | M5 |
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
- RFC 8489 erratum 6268 is pinned by `tests/test_integrity.py::test_rfc8489_b1_printed_vector_only_matches_the_erroneous_length`: the published SHA-256 MAC reproduces only with the wrong length 0x9c.
- RFC 8489 erratum 6290 (bit order of the sec. 18.1 security-feature set) contradicts the sec. 9.2 paragraph 5 text, which says bit 0 is the most significant bit of the first byte. The nonce-cookie security features are not implemented; resolve the contradiction before writing them.
- RFC 8656 sec. 7.4 calls error 442 "Unsupported Transport Address" while sec. 7.2 and sec. 19 call it "Unsupported Transport Protocol"; no erratum is filed (checked 2026-11-13). Sec. 7.2 and sec. 19 are followed.
- RFC 8489 has 3 verified and 2 reported errata (rechecked 2026-11-13); the verified one on sec. 6.2.2 is a typo (8434). RFC 6298 has none. RFC 5892 has one verified, 3312 (appendix A rules apply per occurrence), followed in `precis`. RFC 8264 has 1 on file, RFC 8265 has 1 reported (5479, sec. 3.1, not OpaqueString).
- RFC 8656 has one erratum on file, 8901 (reported, technical): the ICMP attribute figure shows 7-bit and 9-bit fields, and the code reads them as 8 bits each, as ICMP defines.
- RFC 5769 (the test-vector document, informational, current) has one erratum on file, 4776 (held, editorial) proposing a different SOFTWARE string; the printed bytes are the vector and the tests use them.
- RFC 7635 has four errata on file (4826 and 4923 held; 5059 and 5060 reported), all technical, none read in depth.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a WebRTC stack or any SDP handling | `[no]` | a named document requires it |
| DTLS-SRTP or media of any kind: the relayed path is opaque here | `[no]` | a named document requires it |
| a TURN server, which is an operational product rather than a client library | `[no]` | a named document requires it |

## 5. Open questions

- does the ICE agent need to be wire compatible with aioice for a shared test harness
- **Decided in this pass: `credentials.rest_credentials`.** RFC 7635 (checked through rfclib 2026-11-13) is OAuth 2.0 third-party authorization for STUN. It contains no timestamped-username scheme, and a search of the RFC for it found nothing. The row is now a `[no]` non-goal naming the problem, the stub function is removed, and `credentials.oauth-access-token` is the honest RFC 7635 row. Owner: confirm `[no]`, or name a document to cite for the REST scheme (an Internet-Draft, which rfclib does not hold).
- M2 transports: sec. 6.2 is read and the timing is built; sockets and TLS remain (DTLS is `[no]`: no standard-library or `cryptography` path).
- **Decided and built: OpaqueString** is a generated table (IANA precis-tables-6.3.0, CC0) with its source sha256 in `turnkit/_precis_table.py`. Open for the owner: Unicode 6.3.0 refuses code points assigned later (see the `precis.unicode-version` row). RFC 5769 sec. 2.4 and RFC 8489 appendix B.1 print the SASLprep result "TheMatrIX" as the OpaqueString result, which it is not; both vectors run with `prepared=True`.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
