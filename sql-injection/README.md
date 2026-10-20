# Cardinal — Phase 1 (SQL injection, Kathara lab)

A minimal, self-contained [Kathara](https://www.kathara.org/) lab for the SQL
injection scenario: a vulnerable staff-portal webapp behind a Coraza WAF (OWASP
CRS) choke point, a seeded MariaDB, a Locust benign-traffic generator, and an
attacker node
with sqlmap — all observed by a passive monitor.

The webapp is the single system-under-test for **all three** Cardinal scenarios
(the document mandates one environment for SQLi + XSS + insecure-deserialization
under the same live benign traffic). It exposes: the concatenated/parameterized
SQL paths, XSS sinks in every context (HTML body, attribute, JS, URI), and an
object-import endpoint that forwards to `desersvc`. Sessions are serialized into
the `cache` (Redis) tier. Each surface is toggleable per request (`?impl`,
`?enc`, `?deser`) so an attack and its byte-identical benign twin share a route.

The WAF is **live**: the proxy runs Coraza with the OWASP CRS, enforcing on `:80`
(blocks) and detection-only on `:8080` (logs and forwards) — see the topology table
and `proxy/etc/coraza/`. Still deferred to later phases: the IDS stack
(Zeek/Suricata/Snort on the monitor) and the full three-tier segmentation (separate
data-net, perimeter/core firewalls). Phase-1 attacker tooling covers SQLi (sqlmap);
XSS/deser attacker tooling is a later-phase add.

> **New here? See [`docs/TUTORIAL.md`](docs/TUTORIAL.md)** for a full walkthrough — start it,
> browse the portal, run the attacks (automated *and* by hand in the browser),
> and find the captured pcaps/dumps.

## Topology

Two collision domains; only `proxy` sits on both, so it is the sole path from
the external tier to the application — the choke point is enforced by topology.

```
   [Host browser]  ──(./expose-ui.sh, via Docker bridge)──▶  proxy :8080 (portal) · locust :8089

   ===== edgenet (172.30.0.0/24) =====
      │         │          │         │
   locust    attacker    proxy    monitor
    .20        .30        .10       .99
                           │         │       proxy & monitor span both domains;
   ===== appnet (172.31.0.0/24) =====        proxy is the only edge→app path
           │      │      │      │      │
        webapp   db   cache desersvc monitor
          .20   .30    .31    .32     .99
```

| Node     | edgenet     | appnet      | bridge¹ | Role                              |
|----------|-------------|-------------|---------|-----------------------------------|
| proxy    | 172.30.0.10 | 172.31.0.10 | yes     | Coraza WAF (OWASP CRS) + reverse proxy (choke point) |
| locust   | 172.30.0.20 | —           | yes     | benign traffic (web UI :8089)     |
| attacker | 172.30.0.30 | —           | —       | sqlmap / curl                     |
| webapp   | —           | 172.31.0.20 | —       | Flask app (gunicorn :5000)        |
| db       | —           | 172.31.0.30 | —       | MariaDB (seeded `portal` DB)      |
| cache    | —           | 172.31.0.31 | —       | Redis (serialized sessions)       |
| desersvc | —           | 172.31.0.32 | —       | object-reconstruction svc (:8090) |
| monitor  | 172.30.0.99 | 172.31.0.99 | —       | passive tcpdump/tshark capture    |

¹ `proxy[bridged]` / `locust[bridged]` in `lab.conf` give these two an extra NIC on
the Docker **default bridge** (a Docker-assigned `172.17.x` address, not shown). It
carries only host-side UI access via `./expose-ui.sh`; it does **not** bridge the two
collision domains and does not weaken the choke point (`webapp`/`db` stay
single-homed on app-net, unreachable from the edge).

## Prerequisites

- Docker Desktop running.
- Kathara: `pip install kathara` (or `brew install kathara`). See
  <https://www.kathara.org/download.html>.

## Run

```bash
cd sql-injection
./build-images.sh              # build the 6 cardinal/* images (once, or after image changes)
kathara lstart --noterminals   # boot all 6 nodes (~30s; db seeds on first boot)
./expose-ui.sh                 # publish portal -> :8080 and Locust UI -> :8089 (Docker Desktop)
```

### Use it

0. **Browse the portal** — after `./expose-ui.sh`, open <http://localhost:8080>
   (served through the proxy). Log in as `alice` / `alicepw`, search the directory,
   view profiles. This is the same app the attacks target.
1. **Benign traffic** — open <http://localhost:8089> (Locust UI). Set ~10 users,
   spawn rate 2, Start. Requests should succeed with no failures.
2. **Watch traffic** — `kathara connect monitor`, then `tail -f /captures/http_live.log`
   for a live HTTP view of both segments (SQL statements are interleaved in,
   tagged `[DBQUERY]`). Full pcaps are written to `/captures/`
   (`edge-net_*.pcap`, `app-net_*.pcap`), and the **DB query log** (the structural
   cut — every statement as the database received it) to `/captures/db_query.log`.
3. **Attack** — in another terminal:
   ```bash
   kathara connect attacker
   /scripts/run_sqli.sh          # automated sqlmap (dumps the DB once injection is found)
   /scripts/manual_payloads.sh   # hand-crafted payloads (auth bypass, UNION, error, time, stacked)
   ```
4. **Observe** — the monitor shows the attacker's injections interleaved with
   Locust's benign requests on the *same* `/search` and `/login` endpoints.

### Manual checks (from the attacker node)

```bash
curl "http://172.30.0.10/search?q=Alice"                 # benign: seeded results
curl -G http://172.30.0.10/search --data-urlencode "q=' OR '1'='1"   # injection: all rows
curl -G http://172.30.0.10/search --data-urlencode "q=Alice&impl=param"  # safe path (same route)
```

The webapp defaults to the vulnerable **concat** path (`SQL_MODE=concat`). Any
request can flip to the safe path per-request with `?impl=param`, so an attack
and its benign twin traverse the identical route — only the parse tree differs.

Two more per-request toggles drive the structural-defense experiments (see
[`docs/RUNBOOK.md`](docs/RUNBOOK.md)): `?rasp=off|detect|block` enables the RASP
structural detector at the DB call (blocks any input that added query structure),
and `?decode=single|double` adds an extra app-side URL decode — the lever for the
double-encoding WAF bypass (`attacker/scripts/encoding_evasion.sh`).

### XSS and deserialization surfaces (same webapp)

```bash
# XSS — the SAME payload is inert in one context and executes in another.
#   raw (vulnerable) breaks out of the attribute; escape (safe) neutralises it:
curl -G http://172.30.0.10/search --data-urlencode 'q="><script>alert(1)</script>' --data-urlencode 'enc=raw'
curl -G http://172.30.0.10/search --data-urlencode 'q="><script>alert(1)</script>' --data-urlencode 'enc=escape'
# Sinks are rendered on /search (reflected) and /profile, /records/<id> (stored),
# across HTML-body / attribute / JS / URI contexts.

# Insecure deserialization — the webapp forwards the object to desersvc:
#   export a benign blob, re-import it; a crafted pickle would execute on rebuild.
#   (?deser=unsafe reconstructs arbitrary objects; ?deser=safe accepts JSON only.)
# Easiest via the JSON API:
TOKEN=$(curl -s -X POST http://172.30.0.10/api/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
BLOB=$(curl -s http://172.30.0.10/api/settings/export -H "Authorization: Bearer $TOKEN" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["blob"])')
curl -s -X POST 'http://172.30.0.10/api/settings/import?deser=unsafe' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"blob\":\"$BLOB\"}"
```

A parallel **JSON API** mirrors every route under `/api/*` (bearer-token auth
from `/api/login`) for scripted traffic and attacks. See `webapp/README.md` for
the full route/toggle reference.

### Stop / reset

```bash
kathara lclean          # tear down; next lstart re-seeds a clean DB
```

### Extract pcaps (while running)

```bash
docker cp "$(docker ps --format '{{.Names}}' | grep _monitor_)":/captures ./pcaps
```

## Notes & gotchas

- **Web UIs on the host.** Kathara collision domains are pure L2 and, on Docker
  Desktop, `machine[port]` does not actually publish to the host. So `lab.conf`
  gives the `proxy` and `locust` a default-bridge NIC (`…[bridged]="true"`) and
  **`./expose-ui.sh`** runs published `socat` sidecars forwarding the host ports to
  their bridge IPs: portal (via proxy) on `:8080` and Locust on `:8089`. Run it
  after `kathara lstart`; stop with `docker rm -f cardinal-webapp-ui cardinal-locust-ui`.
  (On native-Linux Kathara you can instead use `proxy[port]`/`locust[port]` and skip
  the helper.) The portal is only reachable *inside* the lab otherwise — attacks
  target the proxy's in-lab IP `172.30.0.10`, not a host URL.
- **DB init.** Kathara does not run the mariadb image entrypoint, so `db.startup`
  initialises the data dir, starts `mariadbd`, and imports `/seed.sql` itself.
  The seed also creates the `portal` app user (the entrypoint normally would).
- **App user password** is `portal`; seeded logins are `alice`/`alicepw`,
  `bob`/`bobpw`, `carol`/`carolpw`.
- **UNION arity.** The directory search selects **7** columns
  (`id,name,title,department,email,phone,location`) — UNION payloads must match.
- **Choke point.** `webapp` and `db` share app-net (direct hop, no routing); the
  edge nodes can reach the app *only* through the proxy.

## Layout

```
sql-injection/
├── lab.conf / lab.dep          # Kathara topology + boot order
├── build-images.sh             # builds cardinal/{proxy,webapp,db,cache,desersvc,locust,attacker,monitor}
├── expose-ui.sh                # publishes portal (:8080) + Locust UI (:8089) to the host
├── *.startup                   # per-node boot scripts (IPs + service launch)
├── images/*/Dockerfile         # custom image definitions
├── proxy/etc/caddy/Caddyfile   # Coraza WAF (OWASP CRS) + reverse proxy → webapp:5000
├── proxy/etc/coraza/           # WAF modes: :80 enforce (On), :8080 detection-only
├── webapp/app/                 # Flask app: wsgi.py + portal/ package (routes,
│                               #   templates, static) — mounted at /app
├── db/seed.sql                 # schema + seed (+ portal user) — mounted at /seed.sql
├── cache/                      # Redis node (no mounted files)
├── desersvc/svc.py             # object-reconstruction service — mounted at /svc.py
├── locust/locustfile.py        # benign employee workload
├── attacker/scripts/           # run_sqli.sh, manual_payloads.sh
├── monitor/scripts/capture.sh  # tcpdump pcaps + live tshark + DB query-log ingest
└── shared/                     # Kathara shared dir (/shared on every node);
                                #   db writes db_query.log here, monitor reads it
```
