"""Command line entry point for turnkit.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  turnkit allocate --server turn:example.net:3478 --rest-user u --rest-secret env:SECRET"""


def build_parser():
    return argparse.ArgumentParser(
        prog="turnkit",
        description="STUN messaging and long-term credentials, TURN allocations with permissions and channels, and an ICE agent written to RFC 8445 with Trickle ICE and ICE PAC",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour for a shell. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print("turnkit: no protocol behaviour is implemented yet; see ROADMAP.md", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
