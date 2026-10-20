#!/bin/bash
# Cardinal — double / alternate-encoding WAF evasion (reference §3, row 1).
#
# Thin wrapper around encoding_evasion.py. The real work is in Python so the
# exact double-encoded bytes go on the wire unchanged (curl's --data-urlencode
# would re-encode them and break the demo).
#
# Walks a payload plain -> single-encoded -> double-encoded against the enforcing
# WAF (:80) and the detection baseline (:8080), then shows RASP catching the
# payload that beat the WAF. Prints what each request actually did; check
# /shared/waf_audit.log and /shared/rasp_audit.log for the matched rules/verdicts.
#
# Run:  kathara connect attacker ; /scripts/encoding_evasion.sh
exec python3 /scripts/encoding_evasion.py "$@"
