"""Command line entry point: ``loghunt access.log``."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .hunt import Network, hunt
from .parser import read_lines
from .report import (
    BLOCKLIST_FORMATS,
    terminal,
    to_blocklist,
    to_html,
    to_json,
    use_color,
)
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


_MOMENT = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?",
    re.IGNORECASE,
)


def _moment(text: str) -> int:
    """``2026-10-20``, ``2026-10-20 08:30``, ``2026-10-20T08:30:15+07:00`` as Unix seconds.

    Without an offset the time is UTC, the zone every loghunt output uses.
    """
    match = _MOMENT.fullmatch(text.strip())
    if match is None:
        raise argparse.ArgumentTypeError(
            f"not a date or time: {text!r} (use 2026-10-20, 2026-10-20 08:30 "
            "or 2026-10-20T08:30+07:00)"
        )
    year, month, day, hour, minute, second, zone = match.groups()
    offset = timezone.utc
    if zone and zone.upper() != "Z":
        digits = zone[1:].replace(":", "")
        delta = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        offset = timezone(-delta if zone[0] == "-" else delta)
    try:
        moment = datetime(
            int(year),
            int(month),
            int(day),
            int(hour or 0),
            int(minute or 0),
            int(second or 0),
            tzinfo=offset,
        )
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not a valid time: {text!r} ({error})") from None
    return int(moment.timestamp())


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
        "--blocklist-format",
        choices=BLOCKLIST_FORMATS,
        metavar="FORMAT",
        help="plain (default, one IP per line), nginx (deny rules), apache (Require not ip), "
        "ipset (for ipset restore) or nftables (for nft -f)",
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
    parser.add_argument(
        "--since",
        type=_moment,
        metavar="TIME",
        help="only analyse requests at or after TIME, e.g. 2026-10-20 08:30 (UTC unless an "
        "offset such as +07:00 is given)",
    )
    parser.add_argument(
        "--until", type=_moment, metavar="TIME", help="only analyse requests before TIME"
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


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


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
    if args.blocklist_format and not args.blocklist:
        parser.error("--blocklist-format needs --blocklist FILE")
    if args.since is not None and args.until is not None and args.since >= args.until:
        parser.error("--since must be earlier than --until")
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
        result = hunt(read_lines(args.logs), limits, allow, args.since, args.until)
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
            _write(args.blocklist, to_blocklist(result, args.blocklist_format or "plain"))
            left_out = sum(1 for s in result.suspects if not _is_address(s.ip))
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
