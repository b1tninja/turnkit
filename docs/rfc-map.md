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
| RFC 8265 | Proposed Standard: PRECIS OpaqueString, required by RFC 8489 sec. 9 and 14; not yet implemented | 2017-10 | not checked |

## Errata, 2026-11-13

| Document | On file | Handling |
|---|---|---|
| RFC 8489 | 3 verified (6268 appendix B.1 vector, 6290 bit order of sec. 18.1, 8434 typo), 2 reported | 6268 is pinned by a test; 6290 contradicts sec. 9.2 para 5 and is not implemented |
| RFC 8656 | 1 reported (8901, ICMP attribute figure) | code reads type and code as 8 bits each |
| RFC 5769 | 1 held (4776, editorial, SOFTWARE string) | the printed bytes are the vectors |
| RFC 7635 | 4 on file (4826, 4923 held; 5059, 5060 reported), technical | unread; see ROADMAP |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
