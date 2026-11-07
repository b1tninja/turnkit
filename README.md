# turnkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

turnkit -- STUN, TURN and ICE on asyncio

The NAT traversal stack has a Python owner, but a narrow one. aioice 0.12.1 (2026-11-03) is written for aiortc: one ICE agent with a private TURN implementation bolted on, and its own summary still cites RFC 5245, which RFC 8445 obsoleted in 2018, plus RFC 8863, which changed when an agent may declare failure. stun 1.1.0 (2026-08-01) is a message library, and pystun3 plus aiostun answer only the NAT-type question. turnkit is the reusable half nobody has: a TURN client API with its own allocation lifecycle, and an ICE agent whose spec anchors are the current documents rather than the ones a 2018 codebase inherited.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| aioice | 0.12.1 | 2026-11-03 | aiortc's ICE agent with a private TURN client; summary cites the obsoleted RFC 5245 |
| stun | 1.1.0 | 2026-08-01 | STUN messages and attributes; no TURN or ICE |
| aiostun | 0.6.1 | 2026-01-08 | STUN client over UDP, TCP and TLS |
| pyturn | 0.2.4.1 | 2024-03-25 | test-grade STUN and TURN client |
| turnkit, aiturn, stun-client, iceagent | - | - | all absent from PyPI (2026-11-05) |

What this project intends to add:

- a TURN client usable without importing a media stack: allocate, permission, channel, refresh
- transport coverage in one place: UDP, TCP, TLS and the ALPN negotiation that picks them
- an ICE agent anchored on RFC 8445 plus RFC 8838 and the RFC 8863 failure-wait rule
- REST credentials per RFC 7635 and allocation mobility per RFC 8016
- a sans-IO agent core so check scheduling can be tested on a virtual clock

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 8489 | Proposed Standard | 2020-02 | STUN: transactions, attributes, MESSAGE-INTEGRITY, FINGERPRINT |
| RFC 8656 | Proposed Standard | 2020-02 | TURN: allocations, permissions, channels, the relayed path |
| RFC 8445 | Proposed Standard | 2018-07 | ICE: candidate gathering, checks, nomination |
| RFC 8838 | Proposed Standard | 2021-01 | Trickle ICE: incremental candidates and early checks |
| RFC 8863 | Proposed Standard | 2021-01 | ICE PAC: the minimum wait before declaring failure |
| RFC 7635 | Proposed Standard | 2015-08 | third-party authorization, the TURN REST credential model |
| RFC 8016 | Proposed Standard | 2016-11 | allocation mobility across an address change |

### Errata watch

- RFC 8489 carries 3 verified errata. 6268 (Technical) corrects the Appendix B.1 test vector: the printed message length counts the 20-byte header, and the vector lacks the PASSWORD-ALGORITHM attribute its SHA-256 key needs, so test against the corrected vector, not the published one. 6290 (Technical) fixes the bit order of the sec. 18.1 bit set; 8434 is a typo.
- RFC 8445 is updated by RFC 8863, and RFC 8656 is the successor to RFC 5766 and RFC 6156: do not copy recipes from either predecessor.
- RFC 8838 and RFC 8863 report no errata as of 2026-10-29.

## Module layout

| Module | Responsibility |
|---|---|
| `message` | STUN message, attribute and integrity codec (RFC 8489) |
| `transport` | UDP, TCP and TLS transports with framing (RFC 8489) |
| `allocation` | TURN allocate, refresh, lifetime and reallocation (RFC 8656) |
| `permission` | permissions and channel bindings (RFC 8656) |
| `credentials` | long-term credentials, nonce handling, REST tokens (RFC 8489, RFC 7635) |
| `ice` | ICE agent: candidates, check scheduling, nomination (RFC 8445) |
| `trickle` | incremental candidate exchange (RFC 8838) |
| `sansio` | pure agent core for virtual clock testing |

## What it does not do

- a WebRTC stack or any SDP handling
- DTLS-SRTP or media of any kind: the relayed path is opaque here
- a TURN server, which is an operational product rather than a client library


## Install

```bash
git clone https://github.com/b1tninja/turnkit.git
cd turnkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy turnkit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
