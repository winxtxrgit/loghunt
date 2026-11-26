"""Command line entry point: ``loghunt access.log``."""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import zlib
from pathlib import Path

from . import __version__
from .hunt import Network, hunt
from .parser import read_lines
from .report import blocklist_ips, terminal, to_blocklist, to_html, to_json, use_color
from .rules import Thresholds


def _bounded(low: int, high: int):
    def parse(text: str) -> int:
        value = int(text)
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return value

    return parse


def _network(text: str) -> Network:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an IP address or CIDR range: {text!r}") from None


def _allow(text: str) -> list[Network]:
    """``--allow 203.0.113.0/24`` or ``--allow @file``, one entry per line, # for comments."""
    if not text.startswith("@"):
        return [_network(text)]
    name = text[1:]
    try:
        content = Path(name).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise argparse.ArgumentTypeError(f"cannot read {name}: {error}") from None
    networks = []
    for number, line in enumerate(content.splitlines(), start=1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            networks.append(_network(entry))
        except argparse.ArgumentTypeError as error:
            raise argparse.ArgumentTypeError(f"{name} line {number}: {error}") from None
    return networks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loghunt",
        description="Hunt bots, scanners and botnets in nginx/apache access logs. "
        "Every flagged IP comes with the reasons it was flagged.",
    )
    parser.add_argument(
        "logs",
        nargs="+",
        metavar="LOG",
        help="access log files (combined or common format; .gz works; - is stdin)",
    )
    parser.add_argument("-o", "--report", metavar="FILE", help="write an HTML report to FILE")
    parser.add_argument("--json", metavar="FILE", help="write the findings as JSON (- for stdout)")
    parser.add_argument(
        "--blocklist", metavar="FILE", help="write the suspicious IPs to FILE, one per line"
    )
    parser.add_argument(
        "--allow",
        type=_allow,
        action="append",
        default=[],
        metavar="IP|CIDR|@FILE",
        help="never flag these IPs, e.g. your uptime checks (repeatable; @FILE reads one per line)",
    )
    parser.add_argument(
        "--min-score",
        type=_bounded(0, 100),
        default=Thresholds.min_score,
        metavar="N",
        help="report IPs scoring at least N, 0-100 (default: %(default)s)",
    )
    rules = parser.add_argument_group(
        "thresholds", "raise them for a busy site, lower them for a quiet one"
    )
    for flag, name, high, what in (
        ("--burst", "burst", 1_000_000, "requests in one minute for `burst`"),
        ("--flood", "flood", 1_000_000, "requests in one minute for `flood`"),
        ("--login-posts", "login_posts", 1_000_000, "login POSTs for `brute-force`"),
        ("--probes", "probes", 1_000, "distinct attacker-only paths for `probe-paths`"),
    ):
        rules.add_argument(
            flag,
            dest=name,
            type=_bounded(1, high),
            default=getattr(Thresholds, name),
            metavar="N",
            help=f"{what} (default: %(default)s)",
        )
    parser.add_argument(
        "--top",
        type=_bounded(0, 1_000_000),
        default=15,
        metavar="N",
        help="rows in the terminal summary (default: %(default)s)",
    )
    parser.add_argument(
        "--fail", action="store_true", help="exit with status 1 when anything suspicious is found"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _write(target: str, text: str) -> None:
    if target == "-":
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        Path(target).write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.flood < args.burst:
        # The flood check runs first, so a lower flood would hide every burst.
        parser.error(f"--flood ({args.flood}) must be at least --burst ({args.burst})")
    limits = Thresholds(
        burst=args.burst,
        flood=args.flood,
        login_posts=args.login_posts,
        probes=args.probes,
        min_score=args.min_score,
    )
    # Log lines carry arbitrary text; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        allow = [network for group in args.allow for network in group]
        result = hunt(read_lines(args.logs), limits, allow)
    except (OSError, EOFError, zlib.error) as error:  # EOFError: a truncated .gz
        print(f"loghunt: cannot read the log: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

    # With --json - the terminal summary would corrupt the JSON, so it goes to stderr.
    summary_stream = sys.stderr if args.json == "-" else sys.stdout
    try:
        print(terminal(result, top=args.top, color=use_color(summary_stream)), file=summary_stream)
        written = []
        if args.report:
            _write(args.report, to_html(result, args.logs))
            written.append(f"report: {args.report}")
        if args.blocklist:
            _write(args.blocklist, to_blocklist(result))
            left_out = len(result.suspects) - len(blocklist_ips(result))
            note = f" ({left_out} entries that are not IP addresses left out)" if left_out else ""
            written.append(f"blocklist: {args.blocklist}{note}")
        if args.json:
            _write(args.json, to_json(result))
            if args.json != "-":
                written.append(f"json: {args.json}")
        if written:
            print("\nWrote " + " · ".join(written), file=summary_stream)
    except BrokenPipeError:
        # `loghunt access.log | head`: stop quietly, as other command line tools do.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1
    except OSError as error:
        print(
            f"loghunt: cannot write {error.filename or 'output'}: {error.strerror}", file=sys.stderr
        )
        return 2

    return 1 if args.fail and result.suspects else 0


if __name__ == "__main__":
    raise SystemExit(main())
