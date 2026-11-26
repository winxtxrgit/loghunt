# Roadmap

loghunt 0.1.0 finds attackers in a log you already have. The next releases make it fit a real
server (your own monitoring, your own log format, your own firewall), then let it watch a log as
it grows. The rule stays the same in every release: **rules decide, and every decision is
explained.**

## 0.1.0: ship it

- [ ] Push the release workflow (`dc3c206`) to `main`
- [ ] Add loghunt as a Trusted Publisher on PyPI (environment `pypi`, workflow `release.yml`)
- [ ] Publish GitHub release `v0.1.0`, which uploads to PyPI

## 0.2.0: fit your server

Things every operator needs before trusting the output enough to block anyone.

- [x] `--allow IP|CIDR|@FILE`: IPs that are never reported or blocked (uptime checks, office NAT,
      your own scanners). They still count toward traffic totals.
- [x] Threshold flags (`--login-posts`, `--burst`, `--flood`, `--probes`): a busy shop and a
      personal blog need different numbers.
- [ ] `--since` / `--until`: look at one incident window inside a long log.
- [ ] `--blocklist-format plain|nginx|apache|ipset|nftables`: write something you can load
      directly instead of hand-converting a list.

## 0.3.0: read more logs

- [ ] `--format` taking an nginx `log_format` string, so custom formats (request time, upstream,
      `$http_x_forwarded_for` in the middle) parse without regex editing.
- [ ] JSON-lines logs (nginx `escape=json`, Caddy, Traefik).
- [ ] Report the parse rate per file, and warn when most lines are skipped (wrong format).

## 0.4.0: catch smarter botnets

- [ ] Campaigns that rotate User-Agents: group by request set alone when the set is unusual
      enough (attacker-only paths or login endpoints), not by User-Agent.
- [ ] Network view: many IPs in one /24 (IPv4) or /48 (IPv6) that together cross a threshold.
- [ ] Collapse a blocklist into CIDR ranges when a whole range is flagged.

## 0.5.0: watch live

- [ ] `--follow`: tail a growing log and print new suspects as they cross the threshold, with a
      sliding window so memory stays bounded.
- [ ] Systemd unit and cron examples in the README.

## Not planned

- Blocking by itself. loghunt writes the list; you decide to load it.
- Reverse DNS or any network lookup during analysis. A log analysis should not contact the
  attacker's infrastructure, and results must not depend on the network.
- Machine-learned scores. They cannot explain themselves.
