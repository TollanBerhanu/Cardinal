"""Runtime Application Self-Protection (RASP) — structural detector at the DB call.

This is the live counterpart to the *modeled* detector in
``attacker/scripts/model_bypasses.py``. It implements the defense the reference
(``docs/sqli-reference.pdf`` §2.4) describes:

    db.execute(finalQuery)   <- RASP inspects finalQuery here

By the time a query reaches the driver, every layer of encoding has already been
undone, so the detector sees the *real, final* SQL string. And because the app
knows the shape the developer intended (the parameterized sibling of each
vulnerable query, see ``db.py``), it can do the strong check the reference names:
compare the final query's structure to its intended structure and block any call
where a value that was only ever supposed to carry *data* has instead added query
*structure* (a new clause, keyword, operator, comment, or statement).

Mechanism — *intended-shape differential*:
  ``skeleton(sql)`` reduces a query to a structural fingerprint: every string /
  number literal and bound-parameter placeholder collapses to a single ``VALUE``
  token, keywords are upper-cased, identifiers become ``NAME``, and punctuation /
  operators / comments are kept verbatim. Two queries with the same skeleton
  differ only in their literal *values*; a different skeleton means the input
  changed the *structure*. ``guard()`` flags (detect) or blocks (block) the latter.

Known blind spots (faithful to §2.4, demonstrated in the lab, not bugs):
  * Second-order (``/myteam``): the triggering request carries no injected input to
    correlate, so that path is intentionally left uninstrumented in ``db.py``.
  * In-DB dynamic SQL (``impl=proc``): the malicious query is assembled *inside* the
    stored procedure; the app only ever sees ``CALL search_dir(%s)``.
  * Comment / token tricks are caught here (an injected comment is itself extra
    structure), but the engine's own normalisation can differ from the DB's — the
    lab records what actually happens rather than assuming.
"""
import datetime
import json
import os

try:
    import sqlparse
    from sqlparse import tokens as T
except Exception:  # pragma: no cover - sqlparse is baked into the webapp image
    sqlparse = None
    T = None


AUDIT_LOG = os.environ.get("RASP_AUDIT_LOG", "/shared/rasp_audit.log")


class RaspBlocked(Exception):
    """Raised (in ``block`` mode) before the query executes, so RASP actually
    prevents the call. Carries the verdict for the route to render."""

    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(verdict.get("reason", "blocked by RASP"))


def _structural_token(ttype, value):
    """Map one flattened sqlparse token to its structural marker, or ``None`` to
    drop it (whitespace). Literals and placeholders collapse to ``VALUE`` — the
    one thing an input is *allowed* to be — so only genuine structure survives."""
    if ttype in T.Whitespace:
        return None
    if ttype in T.Comment:
        return "COMMENT"
    if ttype in T.Literal or ttype in T.String or ttype in T.Number:
        return "VALUE"
    if ttype in T.Name.Placeholder:          # the %s of a prepared statement
        return "VALUE"
    if ttype in T.Keyword:
        return value.upper()
    if ttype in T.Name:                       # column/table identifiers
        return "NAME"
    if ttype in T.Operator:
        return value.upper()
    if ttype in T.Punctuation:
        return value
    return value.upper()


def skeleton(sql):
    """Structural fingerprint of a query: a tuple of structure tokens with all
    literal values masked. Same skeleton == same shape, differ only in data."""
    out = []
    for stmt in sqlparse.parse(sql or ""):
        for tok in stmt.flatten():
            marker = _structural_token(tok.ttype, tok.value)
            if marker is not None:
                out.append(marker)
    return tuple(out)


def log_verdict(verdict):
    """Append one JSON record per inspected call to the shared audit log, matching
    the waf_audit.log / db_query.log convention the monitor side ingests."""
    try:
        with open(AUDIT_LOG, "a") as fh:
            fh.write(json.dumps(verdict) + "\n")
    except Exception:
        pass  # logging must never break a request


def guard(final_sql, intended_sql, mode="off", route=None):
    """Inspect a query at execution time.

    ``mode``: ``off`` (no-op), ``detect`` (log the verdict, allow), or ``block``
    (log, and raise :class:`RaspBlocked` when the input added structure).

    Returns the verdict dict (or ``None`` when off / unavailable).
    """
    if not mode or mode == "off":
        return None

    if sqlparse is None:  # misconfigured (RASP on without the dep) — fail open, loudly
        verdict = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "route": route, "mode": mode, "decision": "allow",
            "attack": False, "error": "sqlparse unavailable; rebuild the webapp image",
        }
        log_verdict(verdict)
        return verdict

    final_skel = skeleton(final_sql)
    intended_skel = skeleton(intended_sql)
    attack = final_skel != intended_skel
    decision = "block" if (attack and mode == "block") else ("flag" if attack else "allow")

    verdict = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "route": route,
        "mode": mode,
        "decision": decision,
        "attack": attack,
        "reason": ("input added query structure" if attack
                   else "value stayed a value"),
        "intended_sql": intended_sql,
        "final_sql": final_sql,
        "intended_shape": " ".join(intended_skel),
        "final_shape": " ".join(final_skel),
    }
    log_verdict(verdict)

    if attack and mode == "block":
        raise RaspBlocked(verdict)
    return verdict
