"""Detection rules. Each one looks at a single IP and explains itself when it fires."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .signatures import script_name
from .stats import IPStats


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    score: int
    reason: str


@dataclass(frozen=True)
class Thresholds:
    burst: int = 120  # requests in one minute
    flood: int = 600
    login_posts: int = 20
    probes: int = 3  # distinct probe paths
    error_min_requests: int = 20
    error_ratio: float = 0.5
    campaign_min_ips: int = 3
    campaign_max_paths: int = 30
    min_score: int = 40  # report IPs at or above this score


def _listing(items: list[str], limit: int = 4) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")


def scanner_agent(stats: IPStats, limits: Thresholds) -> Finding | None:
    if stats.scanner is None:
        return None
    return Finding("scanner-agent", 60, f"User-Agent names an attack tool: {stats.scanner}")


def attack_payload(stats: IPStats, limits: Thresholds) -> Finding | None:
    if not stats.payload_hits:
        return None
    plural = "s" if stats.payload_hits != 1 else ""
    reason = (
        f"{stats.payload_hits} request{plural} carry attack payloads, "
        f"e.g. {stats.payload_samples[0]}"
    )
    return Finding("attack-payload", 50, reason)


def probe_paths(stats: IPStats, limits: Thresholds) -> Finding | None:
    count = len(stats.probes)
    if count < limits.probes:
        return None
    score = min(60, 40 + 5 * (count - limits.probes))
    reason = f"Asked for {count} paths only attackers look for: {_listing(sorted(stats.probes))}"
    return Finding("probe-paths", score, reason)


def brute_force(stats: IPStats, limits: Thresholds) -> Finding | None:
    total = stats.login_total
    if total < limits.login_posts:
        return None
    path, count = stats.login_posts.most_common(1)[0]
    where = f"all to {path}" if count == total else f"{count} to {path}"
    return Finding("brute-force", 45, f"{total} login attempts (POST), {where}")


def burst(stats: IPStats, limits: Thresholds) -> Finding | None:
    peak = stats.peak_per_minute
    if peak >= limits.flood:
        return Finding("flood", 50, f"Peak of {peak} requests in one minute")
    if peak >= limits.burst:
        return Finding("burst", 30, f"Peak of {peak} requests in one minute")
    return None


def error_ratio(stats: IPStats, limits: Thresholds) -> Finding | None:
    if stats.requests < limits.error_min_requests:
        return None
    ratio = stats.client_errors / stats.requests
    if ratio < limits.error_ratio:
        return None
    return Finding("error-ratio", 25, f"{ratio:.0%} of {stats.requests:,} requests failed with 4xx")


def script_agent(stats: IPStats, limits: Thresholds) -> Finding | None:
    agent = stats.main_agent
    if agent is None:
        return None
    if agent in ("", "-"):
        return Finding("script-agent", 15, "Sends no User-Agent")
    name = script_name(agent)
    if name:
        return Finding("script-agent", 15, f"User-Agent is an HTTP library, not a browser: {name}")
    return None


Rule = Callable[[IPStats, Thresholds], "Finding | None"]
RULES: tuple[Rule, ...] = (
    scanner_agent,
    attack_payload,
    probe_paths,
    brute_force,
    burst,
    error_ratio,
    script_agent,
)


def evaluate(stats: IPStats, limits: Thresholds) -> list[Finding]:
    return [finding for rule in RULES if (finding := rule(stats, limits)) is not None]
