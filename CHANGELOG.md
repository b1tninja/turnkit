# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

- STUN message codec, attribute scanner and the class and method bit interleave (RFC 8489).
- MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 and FINGERPRINT, checked against RFC 5769
  sections 2.1 to 2.4; the printed RFC 8489 appendix B.1 vector is shown to match only the
  erroneous length of erratum 6268.
- Short-term and long-term keys and USERHASH; OpaqueString is ASCII only.
- The RFC 8656 attributes, error-code attributes and ChannelData.
- Removed the `credentials.rest_credentials` stub: RFC 7635 does not define that scheme.
- Allocation, permissions, transports and ICE remain stubs; see [ROADMAP.md](ROADMAP.md).

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for turnkit.
- `turnkit.apps` namespace reserved for composition that is not protocol behaviour.
