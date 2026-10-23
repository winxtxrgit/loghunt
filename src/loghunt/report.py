"""Render a result as a terminal summary, JSON, a blocklist or a single-file HTML report.

Every string that comes from the log is attacker-controlled, so the HTML report
escapes all of it and loads nothing from the network.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from datetime import datetime, timezone
from html import escape

from . import __version__
from .hunt import Result, Suspect


def _when(ts: int | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, timezone.utc).strftime(fmt)


def _period(start: int | None, end: int | None) -> str:
    """``2026-10-20 01:00 → 02:59``, repeating the date only when the period crosses one."""
    if start is not None and end is not None and _when(start, "%Y%m%d") == _when(end, "%Y%m%d"):
        return f"{_when(start)} → {_when(end, '%H:%M')}"
    return f"{_when(start)} → {_when(end)}"


def _span(seconds: int) -> str:
    hours, rest = divmod(max(0, seconds), 3600)
    minutes = rest // 60
    return f"{hours}h {minutes}m" if hours else f"{minutes}m {rest % 60}s"


# --------------------------------------------------------------------------- terminal


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(text: str) -> str:
    """*text* with control characters spelled out as ``\\xNN``.

    Log fields are attacker-controlled; a raw ESC in an IP or User-Agent could otherwise
    recolour, retitle or rewrite the terminal that shows the summary.
    """
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def use_color(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def terminal(result: Result, top: int = 15, color: bool = False) -> str:
    style = _Style(color)
    width = shutil.get_terminal_size((100, 24)).columns
    out = []
    span = _span((result.end or 0) - (result.start or 0))
    out.append(
        style("loghunt", "1;36")
        + f"  {result.parsed:,} requests · {len(result.stats):,} IPs · {span}"
        + f"  ({_period(result.start, result.end)} UTC)"
    )
    if result.skipped:
        out.append(style(f"         {result.skipped:,} lines were not access log entries", "2"))
    out.append("")

    if not result.suspects:
        out.append(style("No suspicious IPs found.", "32"))
        return "\n".join(out)

    share = result.flagged_requests / max(1, result.parsed)
    out.append(
        style(f"{len(result.suspects)} suspicious IPs", "1")
        + f" sent {share:.0%} of all requests"
        + (f" · {len(result.campaigns)} campaign(s)" if result.campaigns else "")
    )
    out.append("")

    # One row per campaign instead of one per member, so a botnet does not fill the table.
    rows: list[tuple[int, str, str, int, int, str, int]] = []
    in_campaign = {ip for c in result.campaigns for ip in c.ips}
    by_ip = {s.ip: s for s in result.suspects}
    for campaign in result.campaigns:
        members = [by_ip[ip] for ip in campaign.ips if ip in by_ip]
        if not members:
            continue
        top_member = max(members, key=lambda m: m.score)
        rows.append(
            (
                top_member.score,
                top_member.severity,
                f"{len(members)} IPs ({campaign.id})",
                sum(m.stats.requests for m in members),
                max(m.stats.peak_per_minute for m in members),
                _clean(campaign.reason),
                0,
            )
        )
    for suspect in result.suspects:
        if suspect.ip in in_campaign:
            continue
        reasons = [f.reason for f in suspect.findings]
        rows.append(
            (
                suspect.score,
                suspect.severity,
                _clean(suspect.ip),
                suspect.stats.requests,
                suspect.stats.peak_per_minute,
                _clean(reasons[0]),
                len(reasons) - 1,
            )
        )
    rows.sort(key=lambda row: (-row[0], -row[3]))

    shown = rows[:top]
    ip_width = max([len("IP"), *(len(row[2]) for row in shown)])
    header = f"{'SCORE':>5}  {'IP':<{ip_width}}  {'REQS':>7}  {'PEAK/MIN':>8}  WHY"
    out.append(style(header, "2"))
    colors = {"high": "1;31", "medium": "33", "low": "2"}
    why_width = max(24, width - ip_width - 34)
    for score, severity, who, requests, peak, why, more in shown:
        extra = f" (+{more})" if more else ""
        room = why_width - len(extra)
        if len(why) > room:
            why = why[: room - 1] + "…"
        out.append(
            style(f"{score:>5}", colors[severity])
            + f"  {who:<{ip_width}}  {requests:>7,}  {peak:>8,}  {why}{style(extra, '2')}"
        )
    if len(rows) > top:
        out.append(style(f"  … {len(rows) - top} more rows in the report", "2"))

    for campaign in result.campaigns:
        out.append("")
        out.append(
            style(f"Campaign {campaign.id}", "1;35")
            + f"  {len(campaign.ips)} IPs across {campaign.networks} networks"
            + f" · {campaign.total_requests:,} requests"
        )
        out.append(f"  {_clean(campaign.reason)}")
        out.append(style(f"  User-Agent: {_clean(campaign.agent[:90])}", "2"))
        out.append(style(f"  Requests:   {_clean(', '.join(campaign.requests[:4]))}", "2"))
    return "\n".join(out)


# --------------------------------------------------------------------------- json / blocklist


def _suspect_json(suspect: Suspect) -> dict:
    stats = suspect.stats
    return {
        "ip": suspect.ip,
        "score": suspect.score,
        "severity": suspect.severity,
        "requests": stats.requests,
        "peak_per_minute": stats.peak_per_minute,
        "client_errors": stats.client_errors,
        "first_seen": _when(stats.first, "%Y-%m-%dT%H:%M:%SZ"),
        "last_seen": _when(stats.last, "%Y-%m-%dT%H:%M:%SZ"),
        "user_agent": stats.main_agent,
        "findings": [
            {"rule": f.rule, "score": f.score, "reason": f.reason} for f in suspect.findings
        ],
    }


def to_json(result: Result) -> str:
    payload = {
        "version": __version__,
        "lines": result.lines,
        "skipped": result.skipped,
        "ips": len(result.stats),
        "start": _when(result.start, "%Y-%m-%dT%H:%M:%SZ"),
        "end": _when(result.end, "%Y-%m-%dT%H:%M:%SZ"),
        "suspects": [_suspect_json(s) for s in result.suspects],
        "campaigns": [
            {
                "id": c.id,
                "ips": list(c.ips),
                "networks": c.networks,
                "requests": list(c.requests),
                "user_agent": c.agent,
                "total_requests": c.total_requests,
                "reason": c.reason,
            }
            for c in result.campaigns
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def blocklist_ips(result: Result) -> list[str]:
    """Suspicious IPs that are real addresses, normalised.

    The IP column is whatever the log format put first. With X-Forwarded-For logging the
    client writes it, so a value such as ``1.2.3.4;include /x`` must never reach a
    firewall or server config built from this list.
    """
    ips = []
    for suspect in result.suspects:
        try:
            ips.append(str(ipaddress.ip_address(suspect.ip)))
        except ValueError:
            continue
    return ips


def to_blocklist(result: Result) -> str:
    return "".join(f"{ip}\n" for ip in blocklist_ips(result))


# --------------------------------------------------------------------------- html

HTML_ROW_CAP = 5000

_CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#5d6678;--line:#e2e5eb;
--accent:#d6336c;--accent-soft:#fbe4ec;--bar:#c5ccd8;--high:#c92a2a;--medium:#b35c00;
--chip:#eef1f5;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#151b24;--text:#e6e9ef;
--muted:#9aa3b2;--line:#273041;--accent:#ff6b9a;--accent-soft:#3a1a27;--bar:#3a4558;
--high:#ff6b6b;--medium:#ffa94d;--chip:#1e2633}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 12px}
.sub{color:var(--muted);margin:0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:24px;font-variant-numeric:tabular-nums}
.card span{color:var(--muted);font-size:13px}
.card.hot b{color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
svg.timeline{width:100%;height:150px;display:block}
.legend{display:flex;gap:16px;color:var(--muted);font-size:13px;margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.campaign{margin-bottom:12px}
.campaign h3{margin:0 0 4px;font-size:16px}
.campaign p{margin:4px 0}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chip{background:var(--chip);border-radius:6px;padding:2px 8px;font:12px var(--mono)}
code,.mono{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
.tools{display:flex;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
input[type=search]{flex:1;min-width:220px;padding:9px 12px;border-radius:8px;
border:1px solid var(--line);background:var(--panel);color:var(--text);font:inherit}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.ip{white-space:nowrap}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td ul{margin:0;padding-left:18px}
.score{display:inline-block;min-width:38px;text-align:center;border-radius:6px;padding:2px 6px;
font-weight:700;font-variant-numeric:tabular-nums}
.score.high{background:var(--accent-soft);color:var(--high)}
.score.medium{background:var(--chip);color:var(--medium)}
.agent{color:var(--muted);font-size:12px;margin-top:4px}
footer{color:var(--muted);font-size:13px;margin-top:32px}
"""

# The report never needs the network; this also keeps a hostile log from loading anything.
_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"

_JS = """
const q=document.getElementById('filter');
const rows=[...document.querySelectorAll('#suspects tbody tr:not(.more)')];
const n=document.getElementById('shown');
q.addEventListener('input',()=>{const t=q.value.trim().toLowerCase();let c=0;
rows.forEach(r=>{const hit=!t||r.textContent.toLowerCase().includes(t);r.hidden=!hit;if(hit)c++});
n.textContent=c});
"""


def _timeline_svg(rows: list[tuple[int, int, int]]) -> str:
    if not rows:
        return ""
    peak = max(total for _, total, _ in rows) or 1
    width, height = 1000, 150
    step = width / len(rows)
    bars = []
    for i, (start, total, flagged) in enumerate(rows):
        x = i * step
        h_total = total / peak * (height - 4)
        h_flagged = flagged / peak * (height - 4)
        label = escape(f"{_when(start)} UTC: {total:,} requests, {flagged:,} from flagged IPs")
        bars.append(
            f"<g><title>{label}</title>"
            f'<rect x="{x:.1f}" y="{height - h_total:.1f}" width="{max(step - 1, 1):.1f}" '
            f'height="{h_total:.1f}" fill="var(--bar)"/>'
            f'<rect x="{x:.1f}" y="{height - h_flagged:.1f}" width="{max(step - 1, 1):.1f}" '
            f'height="{h_flagged:.1f}" fill="var(--accent)"/></g>'
        )
    return (
        f'<svg class="timeline" viewBox="0 0 {width} {height}" preserveAspectRatio="none" '
        f'role="img" aria-label="Requests over time, flagged IPs highlighted">{"".join(bars)}</svg>'
    )


def _active(first: int, last: int) -> str:
    if _when(first, "%Y%m%d") == _when(last, "%Y%m%d"):
        return f"{_when(first, '%H:%M')}–{_when(last, '%H:%M')}"
    return f"{_when(first, '%m-%d %H:%M')}–{_when(last, '%m-%d %H:%M')}"


def _suspect_row(suspect: Suspect) -> str:
    stats = suspect.stats
    reasons = "".join(f"<li>{escape(f.reason)}</li>" for f in suspect.findings)
    agent = stats.main_agent
    agent_html = f'<div class="agent mono">{escape(agent[:160])}</div>' if agent else ""
    errors = stats.client_errors / stats.requests if stats.requests else 0
    return (
        f'<tr><td><span class="score {suspect.severity}">{suspect.score}</span></td>'
        f'<td class="ip"><span class="mono">{escape(suspect.ip)}</span></td>'
        f'<td class="num">{stats.requests:,}</td>'
        f'<td class="num">{stats.peak_per_minute:,}</td>'
        f'<td class="num">{errors:.0%}</td>'
        f'<td class="num">{escape(_active(stats.first, stats.last))}</td>'
        f"<td><ul>{reasons}</ul>{agent_html}</td></tr>"
    )


def _campaign_block(campaign) -> str:
    chips = "".join(f'<span class="chip">{escape(ip)}</span>' for ip in campaign.ips)
    requests = ", ".join(f"<code>{escape(r)}</code>" for r in campaign.requests[:8])
    if len(campaign.requests) > 8:
        requests += f" and {len(campaign.requests) - 8} more"
    return (
        f'<div class="panel campaign"><h3>Campaign {escape(campaign.id)} · '
        f"{len(campaign.ips)} IPs across {campaign.networks} networks · "
        f"{campaign.total_requests:,} requests</h3>"
        f"<p>{escape(campaign.reason)}</p>"
        f"<p>Every IP sent: {requests}</p>"
        f"<p>User-Agent: <code>{escape(campaign.agent[:200])}</code></p>"
        f'<div class="chips">{chips}</div></div>'
    )


def to_html(result: Result, sources: list[str]) -> str:
    share = result.flagged_requests / max(1, result.parsed)
    high = sum(1 for s in result.suspects if s.severity == "high")
    cards = [
        (f"{result.parsed:,}", "requests analysed", False),
        (f"{len(result.stats):,}", "unique IPs", False),
        (f"{len(result.suspects):,}", f"suspicious IPs ({high} high)", True),
        (f"{len(result.campaigns):,}", "campaigns (botnets)", bool(result.campaigns)),
        (f"{share:.0%}", "of traffic from suspicious IPs", True),
    ]
    cards_html = "".join(
        f'<div class="card{" hot" if hot else ""}"><b>{value}</b><span>{label}</span></div>'
        for value, label, hot in cards
    )
    campaigns_html = "".join(_campaign_block(c) for c in result.campaigns) or (
        '<p class="sub">No coordinated groups found.</p>'
    )
    shown = min(len(result.suspects), HTML_ROW_CAP)
    rows = "".join(_suspect_row(s) for s in result.suspects[:HTML_ROW_CAP])
    if len(result.suspects) > HTML_ROW_CAP:
        hidden = len(result.suspects) - HTML_ROW_CAP
        rows += (
            f'<tr class="more"><td colspan="7" class="sub">{hidden:,} more suspicious IPs '
            "are left out to keep this file small; --json and --blocklist list all of them."
            "</td></tr>"
        )
    limits = result.limits
    names = ", ".join(escape(os.path.basename(s) or s) for s in sources)
    generated = _when(int(datetime.now(timezone.utc).timestamp()))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<title>loghunt report</title><style>{_CSS}</style></head>
<body><main>
<h1>loghunt report</h1>
<p class="sub">{names} · {_period(result.start, result.end)} UTC
({_span((result.end or 0) - (result.start or 0))})</p>
<div class="cards">{cards_html}</div>

<h2>Traffic over time</h2>
<div class="panel">{_timeline_svg(result.timeline())}
<div class="legend"><span><i style="background:var(--bar)"></i>all requests</span>
<span><i style="background:var(--accent)"></i>from suspicious IPs</span></div></div>

<h2>Campaigns</h2>
{campaigns_html}

<h2>Suspicious IPs</h2>
<div class="tools"><input id="filter" type="search" placeholder="Filter by IP, rule or User-Agent"
aria-label="Filter suspicious IPs"><span class="sub"><span id="shown">{shown}</span>
shown</span></div>
<div class="table-wrap"><table id="suspects"><thead><tr><th>Score</th><th>IP</th>
<th class="num">Requests</th><th class="num">Peak/min</th><th class="num">4xx</th>
<th class="num">Active (UTC)</th><th>Why</th></tr></thead><tbody>{rows}</tbody></table></div>

<footer>Generated by loghunt {__version__} on {generated} UTC.
{result.skipped:,} of {result.lines:,} lines were not access log entries.
Reporting IPs scoring {limits.min_score} or more. Thresholds: burst {limits.burst}/min,
flood {limits.flood}/min, {limits.login_posts} login POSTs, {limits.probes} probe paths,
{limits.error_ratio:.0%} 4xx over {limits.error_min_requests}+ requests,
campaigns of {limits.campaign_min_ips}+ IPs.</footer>
</main><script>{_JS}</script></body></html>
"""
