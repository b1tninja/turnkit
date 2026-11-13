# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 8489 | Proposed Standard | 2020-02 | 2026-11-05 |
| RFC 8656 | Proposed Standard | 2020-02 | 2026-11-05 |
| RFC 8445 | Proposed Standard | 2018-07 | 2026-11-05 |
| RFC 8838 | Proposed Standard | 2021-01 | 2026-11-05 |
| RFC 8863 | Proposed Standard | 2021-01 | 2026-11-05 |
| RFC 7635 | Proposed Standard (OAuth 2.0 third-party authorization for STUN; it does not define a REST credential) | 2015-08 | 2026-11-13 |
| RFC 8016 | Proposed Standard | 2016-11 | 2026-11-05 |
| RFC 5769 | Informational, current: test vectors for STUN (the M1 evidence) | 2010-04 | 2026-11-13 |
| RFC 8265 | Proposed Standard: PRECIS OpaqueString, required by RFC 8489 sec. 9 and 14; implemented in `turnkit/precis.py` | 2017-10 | 2026-11-13 |
| RFC 8264 | Proposed Standard: PRECIS framework; sec. 4.3 FreeformClass, sec. 5.2 rules | 2017-10 | 2026-11-13 |
| RFC 5892 | Proposed Standard: IDNA code points; appendix A contextual rules, used by FreeformClass | 2010-08 | 2026-11-13 |
| RFC 6298 | Proposed Standard: TCP retransmission timer; sec. 2 is the RTO estimator RFC 8489 sec. 6.2.1 points to | 2011-06 | 2026-11-13 |
| IANA precis-tables-6.3.0 | Registry (CC0): derived property values for Unicode 6.3.0, 1502 records, updated 2017-10-06; the undated `precis-tables` URL redirects to it | 2017 | 2026-11-13 |

## Errata, 2026-11-13

| Document | On file | Handling |
|---|---|---|
| RFC 8489 | 3 verified (6268 appendix B.1 vector, 6290 bit order of sec. 18.1, 8434 typo), 2 reported | 6268 is pinned by a test; 6290 contradicts sec. 9.2 para 5 and is not implemented |
| RFC 8656 | 1 reported (8901, ICMP attribute figure) | code reads type and code as 8 bits each |
| RFC 5769 | 1 held (4776, editorial, SOFTWARE string) | the printed bytes are the vectors |
| RFC 7635 | 4 on file (4826, 4923 held; 5059, 5060 reported), technical | unread; see ROADMAP |

PRECIS table provenance: `https://www.iana.org/assignments/precis-tables-6.3.0/precis-tables-6.3.0.xml`, fetched raw on 2026-11-13 (252,311 bytes, sha256 `9d3a32bf56ba84366335d423942e29f72eb27765bf83567523df926e71572d8a`, Last-Modified 2026-10-13); the file is not vendored. `tools/gen_precis_table.py <file>` regenerates `turnkit/_precis_table.py`, which carries the URL, the sha256 and the registry date. The primarysource `iana` collection did not hold this registry on the day, so the raw registry was read.

Spec findings of 2026-11-13: (1) RFC 5769 sec. 2.4 and RFC 8489 appendix B.1 give the password "The<U+00AD>M<U+00AA>tr<U+2168>" and its result "TheMatrIX" as OpaqueString processing; that is SASLprep (RFC 4013, NFKC). OpaqueString (RFC 8265 sec. 4.2.2) keeps U+00AA and U+2168 and the table marks U+00AD DISALLOWED, so the vector cannot be reproduced by the profile it names. RFC 8489 sec. 14.3 itself says SASLprep and OpaqueString differ. (2) RFC 8656 sec. 7.4 names 442 "Unsupported Transport Address"; sec. 7.2 and sec. 19 say "Protocol". (3) RFC 8489 sec. 6.2.1 and RFC 6298 sec. 2.4 disagree on rounding the RTO to a second; see `transport.rto-floor`.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
