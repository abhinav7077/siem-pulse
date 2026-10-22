# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The SIEM Pulse Authors
"""
dashboard.py
============
A small built-in web dashboard and API (Python standard library only).

    siem-pulse --dashboard                       # http://127.0.0.1:8080
    siem-pulse --schedule --dashboard            # checks + dashboard in one process

Pages and endpoints:
    /                overview: last run, coverage per client, trend, open issues, ATT&CK gaps
    /client?name=X   every device of one client in the last run
    /api/summary     JSON summary            /api/issues   JSON open issues
    /api/runs        JSON run history        /metrics      Prometheus metrics
    /healthz         200 when a run finished recently, 503 otherwise (no auth)

config.yaml:

    dashboard:
      host: 127.0.0.1
      port: 8080
      users:                                   # role-based access by token
        - name: soc
          token_secret: DASHBOARD_TOKEN_SOC    # secret holding the token
          clients: "*"                         # every client
        - name: acme
          token_secret: DASHBOARD_TOKEN_ACME
          clients: ["Acme Corp"]               # only this client's devices
      allow_anonymous: false                   # only matters when no users are set
      metrics_public: false                    # /metrics without a token

Sign in by opening /?token=<token> once (stored in an HttpOnly cookie) or send
"Authorization: Bearer <token>". With no users configured the dashboard only
starts on a loopback address, unless allow_anonymous is true.
"""

import hmac
import html
import ipaddress
import json
import logging
import threading
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import __version__
from .coverage import blind_spots, coverage_by_client, device_type_map
from .credentials import get_secret
from .state_store import ISSUE_STATUSES, StateStore, from_iso

logger = logging.getLogger(__name__)

COOKIE = "siem_pulse_token"


# ─── Access control ───────────────────────────────────────────────────────────

class User:
    def __init__(self, name: str, clients):
        self.name = name
        self.all_clients = clients in ("*", ["*"], None)
        self.clients = set() if self.all_clients else {str(c).lower() for c in clients}

    def can_see(self, client: Optional[str]) -> bool:
        return self.all_clients or str(client or "").lower() in self.clients

    def filter(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return rows if self.all_clients else [r for r in rows if self.can_see(r.get("client_name"))]


ANONYMOUS = User("anonymous", "*")


def load_users(config: dict) -> List[tuple]:
    """[(token, User)] from dashboard.users; users whose secret is missing are skipped."""
    users = []
    for entry in (config.get("dashboard") or {}).get("users") or []:
        token = get_secret(config, entry.get("token_secret", ""))
        if not token:
            logger.warning(f"Dashboard user '{entry.get('name')}' has no token ({entry.get('token_secret')}) — skipped")
            continue
        users.append((token, User(entry.get("name", "user"), entry.get("clients", "*"))))
    return users


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


# ─── Data ─────────────────────────────────────────────────────────────────────

def heartbeat_status(
    config: dict, last_run: Optional[Dict[str, Any]], now: Optional[datetime] = None
) -> Dict[str, Any]:
    """Is the monitor itself running? max age defaults to 2 x interval + 5 minutes."""
    now = now or datetime.now(tz=timezone.utc)
    interval = float((config.get("scheduler") or {}).get("interval_minutes", 60))
    max_age = float((config.get("heartbeat") or {}).get("max_age_minutes", interval * 2 + 5))
    finished = from_iso(last_run.get("finished_at")) if last_run else None
    age = (now - finished).total_seconds() / 60 if finished else None
    return {
        "ok": age is not None and age <= max_age,
        "last_run_finished_at": last_run.get("finished_at") if last_run else None,
        "age_minutes": round(age, 1) if age is not None else None,
        "max_age_minutes": max_age,
    }


class DashboardData:
    def __init__(self, config: dict, store: StateStore):
        self.config = config
        self.store = store

    def last_results(self, user: User) -> List[Dict[str, Any]]:
        run = self.store.last_run()
        if not run:
            return []
        rows = user.filter(self.store.run_results(run["id"]))
        for r in rows:
            r["findings"] = [f for f in (r.get("findings") or "").split("; ") if f]
        return rows

    def summary(self, user: User) -> Dict[str, Any]:
        run = self.store.last_run()
        results = self.last_results(user)
        counts = {s: sum(1 for r in results if r["status"] == s) for s in ("healthy", "stale", "error", "degraded")}
        return {
            "version": __version__,
            "user": user.name,
            "last_run": {k: run[k] for k in ("id", "started_at", "finished_at", "duration_seconds", "scope")}
            if run else None,
            "totals": {"devices": len(results), **counts,
                       "suppressed": sum(1 for r in results if r.get("suppressed") and r["status"] != "healthy")},
            "coverage": coverage_by_client(results),
            "blind_spots": blind_spots(results, self.config),
            "heartbeat": heartbeat_status(self.config, run),
        }

    def issues(self, user: User) -> List[Dict[str, Any]]:
        issues = user.filter(self.store.open_issues())
        for i in issues:
            i.pop("tickets", None)
        return sorted(issues, key=lambda i: (str(i.get("client_name")), str(i.get("device_name"))))

    def trend(self, user: User, limit: int = 60) -> List[Dict[str, Any]]:
        runs = list(reversed(self.store.recent_runs(limit)))
        if user.all_clients:
            return [{"at": r["finished_at"], "total": r["total"], "healthy": r["healthy"]} for r in runs]
        points = []
        for r in runs:  # per-client users: recompute from that run's results
            rows = user.filter(self.store.run_results(r["id"]))
            points.append({"at": r["finished_at"], "total": len(rows),
                           "healthy": sum(1 for x in rows if x["status"] == "healthy")})
        return points

    def runs(self, user: User, limit: int = 100) -> List[Dict[str, Any]]:
        if user.all_clients:
            return self.store.recent_runs(limit)
        return [{"id": None, **p} for p in self.trend(user, limit)]


# ─── Prometheus ───────────────────────────────────────────────────────────────

def _label(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def prometheus_metrics(config: dict, store: StateStore, user: User = ANONYMOUS) -> str:
    data = DashboardData(config, store)
    run = store.last_run()
    results = data.last_results(user)
    lines = [
        "# HELP siem_pulse_up 1 if the last run finished within the heartbeat window.",
        "# TYPE siem_pulse_up gauge",
        f"siem_pulse_up {1 if heartbeat_status(config, run)['ok'] else 0}",
    ]
    if run:
        finished = from_iso(run["finished_at"])
        lines += [
            "# HELP siem_pulse_last_run_timestamp_seconds When the last run finished.",
            "# TYPE siem_pulse_last_run_timestamp_seconds gauge",
            f"siem_pulse_last_run_timestamp_seconds {finished.timestamp():.0f}",
            "# HELP siem_pulse_last_run_duration_seconds How long the last run took.",
            "# TYPE siem_pulse_last_run_duration_seconds gauge",
            f"siem_pulse_last_run_duration_seconds {float(run.get('duration_seconds') or 0):.2f}",
        ]
    counts: Dict[tuple, int] = {}
    for r in results:
        key = (r.get("client_name"), r.get("siem_platform"), r["status"])
        counts[key] = counts.get(key, 0) + 1
    lines += ["# HELP siem_pulse_devices Devices by client, SIEM and status in the last run.",
              "# TYPE siem_pulse_devices gauge"]
    for (client, siem, status), n in sorted(counts.items(), key=lambda kv: tuple(map(str, kv[0]))):
        labels = f'client="{_label(client)}",siem="{_label(siem)}",status="{_label(status)}"'
        lines.append(f"siem_pulse_devices{{{labels}}} {n}")
    lines += ["# HELP siem_pulse_client_coverage_score Criticality-weighted healthy percentage per client.",
              "# TYPE siem_pulse_client_coverage_score gauge"]
    for client, c in sorted(coverage_by_client(results).items()):
        lines.append(f'siem_pulse_client_coverage_score{{client="{_label(client)}"}} {c["score"]}')
    if (config.get("metrics") or {}).get("per_device", True):
        lines += ["# HELP siem_pulse_device_hours_since_last_log Hours since each device's last log.",
                  "# TYPE siem_pulse_device_hours_since_last_log gauge"]
        for r in results:
            if r.get("hours_since_last_log") is not None:
                lines.append(
                    f'siem_pulse_device_hours_since_last_log{{client="{_label(r.get("client_name"))}",'
                    f'device="{_label(r.get("device_name"))}",siem="{_label(r.get("siem_platform"))}"}} '
                    f'{float(r["hours_since_last_log"]):.2f}'
                )
    return "\n".join(lines) + "\n"


# ─── HTML ─────────────────────────────────────────────────────────────────────

STYLE = """
:root { --bg:#f6f7f9; --card:#fff; --text:#1d232b; --muted:#5f6b7a; --line:#e3e7ec;
        --ok:#1f8f4e; --bad:#c0392b; --warn:#c77d00; --deg:#d35400; --accent:#2563eb; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12161c; --card:#1b212a; --text:#e6eaef; --muted:#9aa6b4; --line:#2b333e;
          --ok:#3fbf73; --bad:#ef6b5b; --warn:#f0b13a; --deg:#f0883e; --accent:#6aa3ff; } }
* { box-sizing:border-box } body { margin:0; font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;
  background:var(--bg); color:var(--text) }
header { padding:16px 24px; border-bottom:1px solid var(--line); background:var(--card);
  display:flex; gap:16px; align-items:baseline; flex-wrap:wrap }
header h1 { font-size:18px; margin:0 } header .meta { color:var(--muted) }
main { padding:20px 24px; max-width:1300px; margin:auto }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:20px }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px }
.card .n { font-size:26px; font-weight:650 } .card .l { color:var(--muted) }
h2 { font-size:15px; margin:26px 0 10px }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line);
  border-radius:10px; overflow:hidden }
th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top }
th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em }
tr:last-child td { border-bottom:0 } a { color:var(--accent); text-decoration:none }
.s-healthy { color:var(--ok) } .s-stale { color:var(--bad) } .s-error { color:var(--warn) }
.s-degraded { color:var(--deg) } .muted { color:var(--muted) }
.bar { height:8px; border-radius:4px; background:var(--line); width:140px; display:inline-block;
  vertical-align:middle; margin-right:8px }
.bar > span { display:block; height:100%; border-radius:4px; background:var(--ok) }
.wrap { overflow-x:auto } svg { width:100%; height:140px; background:var(--card); border:1px solid var(--line);
  border-radius:10px }
.hb-bad { color:var(--bad); font-weight:600 }
"""


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def trend_svg(points: List[Dict[str, Any]]) -> str:
    if len(points) < 2:
        return '<p class="muted">Trend appears after two runs.</p>'
    width, height, pad = 1000, 140, 12
    values = [100.0 * p["healthy"] / p["total"] if p["total"] else 100.0 for p in points]
    step = (width - 2 * pad) / (len(values) - 1)
    coords = [(pad + i * step, height - pad - (v / 100) * (height - 2 * pad)) for i, v in enumerate(values)]
    path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(coords))
    last = values[-1]
    return (f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" '
            f'aria-label="Healthy percentage over the last {len(values)} runs, now {last:.0f}%">'
            f'<path d="{path}" fill="none" stroke="var(--accent)" stroke-width="2.5" '
            f'vector-effect="non-scaling-stroke"/></svg>'
            f'<p class="muted">Healthy share over the last {len(values)} runs — now {last:.1f}%</p>')


def page(title: str, body: str, user: User) -> str:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{esc(title)}</title><style>{STYLE}</style></head><body>"
            f"<header><h1><a href='/'>SIEM Pulse</a></h1><span class='meta'>{esc(title)}</span>"
            f"<span class='meta' style='margin-left:auto'>signed in as {esc(user.name)} · v{esc(__version__)}</span>"
            f"</header><main>{body}</main></body></html>")


def render_overview(data: DashboardData, user: User) -> str:
    s = data.summary(user)
    t = s["totals"]
    hb = s["heartbeat"]
    last = s["last_run"]
    when = esc(last["finished_at"][:16].replace("T", " ") + " UTC") if last and last["finished_at"] else "never"
    hb_html = ("" if hb["ok"] else
               f"<p class='hb-bad'>⚠ No completed run for {esc(hb['age_minutes'] or '∞')} minutes "
               f"(expected every {esc(hb['max_age_minutes'])} min or less). Is the scheduler running?</p>")
    cards = "".join(
        f"<div class='card'><div class='n {cls}'>{n}</div><div class='l'>{label}</div></div>"
        for n, label, cls in [
            (t["devices"], "devices", ""), (t["healthy"], "healthy", "s-healthy"), (t["stale"], "stale", "s-stale"),
            (t["error"], "errors", "s-error"), (t["degraded"], "degraded", "s-degraded"),
            (t["suppressed"], "suppressed", "muted"),
        ]
    )
    coverage_rows = "".join(
        f"<tr><td><a href='/client?name={quote(client)}'>{esc(client)}</a></td>"
        f"<td><span class='bar'><span style='width:{c['score']}%'></span></span>{c['score']:.1f}%</td>"
        f"<td>{c['devices']}</td><td class='s-stale'>{c['down'] or ''}</td>"
        f"<td class='s-degraded'>{c['degraded'] or ''}</td><td class='muted'>{c['suppressed'] or ''}</td></tr>"
        for client, c in sorted(s["coverage"].items(), key=lambda kv: kv[1]["score"])
    ) or "<tr><td colspan='6' class='muted'>No runs yet.</td></tr>"
    issues = data.issues(user)
    issue_rows = "".join(
        f"<tr><td>{esc(i['device_name'])}<div class='muted'>{esc(i.get('ip_address'))}</div></td>"
        f"<td>{esc(i.get('client_name'))}</td><td>{esc(str(i.get('siem_platform') or '').upper())}</td>"
        f"<td class='s-{esc(i['status'])}'>{esc(i['status'])}</td><td>{esc(i.get('criticality'))}</td>"
        f"<td>{esc((i.get('since') or '')[:16].replace('T', ' '))}</td>"
        f"<td>{esc(i.get('error') or ('last log ' + str(i.get('last_log_time') or 'never')))}"
        f"{'<div class=muted>🔕 ' + esc(i['suppressed']) + '</div>' if i.get('suppressed') else ''}</td></tr>"
        for i in issues
    ) or "<tr><td colspan='7' class='muted'>No open issues. 🎉</td></tr>"
    spot_rows = "".join(
        f"<tr><td>{esc(client)}</td><td>{esc(item['data_source'])} <span class='muted'>{esc(item['id'])}</span></td>"
        f"<td>{esc(', '.join(item['down']))}</td></tr>"
        for client, items in s["blind_spots"].items() for item in items
    )
    spots = (f"<h2>ATT&amp;CK blind spots</h2><div class='wrap'><table><tr><th>Client</th><th>Data source</th>"
             f"<th>Devices down</th></tr>{spot_rows}</table></div>") if spot_rows else ""
    body = (f"{hb_html}<p class='muted'>Last run: {when}</p><div class='cards'>{cards}</div>"
            f"<h2>Trend</h2>{trend_svg(data.trend(user))}"
            f"<h2>Coverage by client</h2><div class='wrap'><table><tr><th>Client</th><th>Coverage</th>"
            f"<th>Devices</th><th>Down</th><th>Degraded</th><th>Suppressed</th></tr>{coverage_rows}</table></div>"
            f"<h2>Open issues ({len(issues)})</h2><div class='wrap'><table><tr><th>Device</th><th>Client</th>"
            f"<th>SIEM</th><th>Status</th><th>Criticality</th><th>Since (UTC)</th><th>Details</th></tr>"
            f"{issue_rows}</table></div>{spots}")
    return page("Overview", body, user)


def render_client(data: DashboardData, user: User, client: str) -> Optional[str]:
    if not user.can_see(client):
        return None
    rows = [r for r in data.last_results(user) if str(r.get("client_name")).lower() == client.lower()]
    order = {"stale": 0, "error": 1, "degraded": 2, "healthy": 3}
    rows.sort(key=lambda r: (order.get(r["status"], 9), str(r.get("device_name"))))
    types = device_type_map(data.config)
    body_rows = "".join(
        f"<tr><td>{esc(r['device_name'])}<div class='muted'>{esc(r.get('ip_address'))}</div></td>"
        f"<td>{esc(str(r.get('siem_platform') or '').upper())}</td>"
        f"<td class='s-{esc(r['status'])}'>{esc(r['status'])}</td>"
        f"<td>{esc(r.get('criticality'))}</td><td>{esc(r.get('device_type') or '')}"
        f"<div class='muted'>{esc(', '.join(types.get(str(r.get('device_type') or ''), [])))}</div></td>"
        f"<td>{esc(r.get('last_log_time') or '')}</td>"
        f"<td>{esc(r.get('error') or '; '.join(r.get('findings') or []))}"
        f"{'<div class=muted>🔕 ' + esc(r['suppressed']) + '</div>' if r.get('suppressed') else ''}</td></tr>"
        for r in rows
    ) or "<tr><td colspan='7' class='muted'>No devices for this client in the last run.</td></tr>"
    body = (f"<p><a href='/'>← Overview</a></p><div class='wrap'><table><tr><th>Device</th><th>SIEM</th>"
            f"<th>Status</th><th>Criticality</th><th>Type / ATT&amp;CK data sources</th><th>Last log</th>"
            f"<th>Details</th></tr>{body_rows}</table></div>")
    return page(client, body, user)


# ─── HTTP server ──────────────────────────────────────────────────────────────

def make_handler(config: dict, store: StateStore, users: List[tuple], anonymous_ok: bool):
    dash_cfg = config.get("dashboard") or {}
    metrics_public = bool(dash_cfg.get("metrics_public", False))
    data = DashboardData(config, store)

    class Handler(BaseHTTPRequestHandler):
        server_version = f"siem-pulse/{__version__}"

        def log_message(self, fmt, *args):  # route access logs through logging
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _token(self, query) -> Optional[str]:
            header = self.headers.get("Authorization", "")
            if header.lower().startswith("bearer "):
                return header[7:].strip()
            if query.get("token"):
                return query["token"][0]
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return unquote(cookie[COOKIE].value) if COOKIE in cookie else None

        def _user(self, query) -> Optional[User]:
            token = self._token(query)
            if token:
                for known, user in users:
                    if hmac.compare_digest(token.encode(), known.encode()):
                        return user
                return None
            return ANONYMOUS if anonymous_ok else None

        def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8", extra=None):
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
                             "frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, status: int, obj: Any):
            self._send(status, json.dumps(obj, default=str, indent=2), "application/json")

        def do_GET(self):  # noqa: N802 (http.server naming)
            url = urlparse(self.path)
            query = parse_qs(url.query)
            try:
                if url.path == "/healthz":
                    status = heartbeat_status(config, store.last_run())
                    return self._json(200 if status["ok"] else 503, status)

                if url.path == "/metrics" and metrics_public:
                    return self._send(200, prometheus_metrics(config, store), "text/plain; version=0.0.4")

                user = self._user(query)
                if user is None:
                    hint = "<p>Open this page with <code>?token=…</code> or send a Bearer token.</p>"
                    return self._send(401, page("Sign in required", hint, User("nobody", [])),
                                      extra={"WWW-Authenticate": 'Bearer realm="siem-pulse"'})

                if query.get("token") and url.path in ("/", "/client"):
                    # Remember the token in a cookie and drop it from the URL
                    clean = url.path + (f"?name={quote(query['name'][0])}" if query.get("name") else "")
                    cookie = (f"{COOKIE}={quote(query['token'][0], safe='')}; HttpOnly; SameSite=Strict; "
                              "Path=/; Max-Age=43200")
                    return self._send(303, "", extra={"Location": clean, "Set-Cookie": cookie})

                if url.path == "/":
                    return self._send(200, render_overview(data, user))
                if url.path == "/client":
                    html_page = render_client(data, user, (query.get("name") or [""])[0])
                    return self._send(200, html_page) if html_page else self._send(403, page(
                        "Forbidden", "<p>You do not have access to this client.</p>", user))
                if url.path == "/api/summary":
                    return self._json(200, data.summary(user))
                if url.path == "/api/issues":
                    return self._json(200, data.issues(user))
                if url.path == "/api/runs":
                    return self._json(200, data.runs(user))
                if url.path == "/metrics":
                    return self._send(200, prometheus_metrics(config, store, user), "text/plain; version=0.0.4")
                return self._send(404, page("Not found", "<p>Nothing here.</p>", user))
            except Exception as e:  # never leak a traceback to the browser
                logger.exception(f"Dashboard error on {url.path}: {e}")
                return self._send(500, "<h1>Internal error</h1>")

    return Handler


def build_server(config: dict, host: Optional[str] = None, port: Optional[int] = None):
    dash_cfg = config.get("dashboard") or {}
    host = host if host is not None else dash_cfg.get("host", "127.0.0.1")
    port = int(port if port is not None else dash_cfg.get("port", 8080))
    users = load_users(config)
    anonymous_ok = not users and (is_loopback(host) or bool(dash_cfg.get("allow_anonymous", False)))
    if not users and not anonymous_ok:
        raise SystemExit(
            f"Refusing to serve the dashboard on {host} without access control. Configure dashboard.users "
            "(recommended) or set dashboard.allow_anonymous: true."
        )
    if anonymous_ok:
        logger.warning("Dashboard has no users configured — anyone who can reach it sees every client.")
    store = StateStore.from_config(config)
    server = ThreadingHTTPServer((host, port), make_handler(config, store, users, anonymous_ok))
    server.daemon_threads = True
    return server


def serve(config: dict, host: Optional[str] = None, port: Optional[int] = None, background: bool = False):
    server = build_server(config, host, port)
    address = f"http://{server.server_address[0]}:{server.server_address[1]}"
    logger.info(f"Dashboard listening on {address}")
    if background:
        thread = threading.Thread(target=server.serve_forever, name="dashboard", daemon=True)
        thread.start()
        return server
    print(f"\n  SIEM Pulse dashboard: {address}  (Ctrl+C to stop)\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return server


__all__ = ["serve", "build_server", "prometheus_metrics", "heartbeat_status", "DashboardData", "ISSUE_STATUSES"]
