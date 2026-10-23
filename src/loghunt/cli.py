"""Command line entry point: ``loghunt access.log``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .hunt import hunt
from .parser import read_lines
from .report import terminal, to_blocklist, to_html, to_json, use_color
from .rules import Thresholds


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
        "--min-score",
        type=int,
        default=Thresholds.min_score,
        metavar="N",
        help="report IPs scoring at least N, 0-100 (default: %(default)s)",
    )
    parser.add_argument(
        "--top",
        type=int,
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
    args = build_parser().parse_args(argv)
    # Log lines carry arbitrary text; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        result = hunt(read_lines(args.logs), Thresholds(min_score=args.min_score))
    except OSError as error:
        print(f"loghunt: {error}", file=sys.stderr)
        return 2

    # With --json - the terminal summary would corrupt the JSON, so it goes to stderr.
    summary_stream = sys.stderr if args.json == "-" else sys.stdout
    print(terminal(result, top=args.top, color=use_color(summary_stream)), file=summary_stream)

    written = []
    if args.report:
        _write(args.report, to_html(result, args.logs))
        written.append(f"report: {args.report}")
    if args.blocklist:
        _write(args.blocklist, to_blocklist(result))
        written.append(f"blocklist: {args.blocklist}")
    if args.json:
        _write(args.json, to_json(result))
        if args.json != "-":
            written.append(f"json: {args.json}")
    if written:
        print("\nWrote " + " · ".join(written), file=summary_stream)

    return 1 if args.fail and result.suspects else 0


if __name__ == "__main__":
    raise SystemExit(main())
