"""Directory search -- the SQLi anchor, reflected-XSS sink, and the surface we
use to demonstrate SERVER-SIDE defenses (Tiers 1-3) and the documented attacks
that bypass them.

Toggles (all per request):
  ?impl=concat|param|proc   SQL path (proc = stored-procedure dynamic SQL, Tier 2)
  ?serversan=denylist|escape|allowlist   server-side input sanitization (Tier 1)
  ?id=<expr>                numeric-context filter (Tier 1 escape blind spot)
  ?sort=<col>               ORDER BY identifier, concatenated (Tier 2 param hole)
"""
from urllib.parse import unquote_to_bytes

from flask import Blueprint, g, redirect, render_template, request, url_for

from ..config import Config, resolve
from ..db import (get_conn, SEARCH_IMPLS, filter_directory_by_id,
                  search_directory_param_sorted, get_user_status,
                  secondorder_lookup, search_directory_gbk)
from ..rasp import RaspBlocked
from ..sanitize_server import purify_server

bp = Blueprint("directory", __name__)


def _rasp_blocked_page(verdict):
    """Render the search page as a 403 when RASP blocks the call."""
    return render_template(
        "search.html", active_nav="directory", term="", results=[],
        impl="rasp-blocked",
        executed_sql="[RASP] blocked: input added query structure.\n"
                     "intended: " + verdict.get("intended_shape", "") + "\n"
                     "final:    " + verdict.get("final_shape", ""),
    ), 403


def _raw_q_bytes(query_string: bytes) -> bytes:
    """Recover the raw, percent-decoded BYTES of ?q=... straight from the request
    line. The charset-confusion attack hinges on a 0xbf lead byte, which Flask's
    normal ``request.args`` decoding would have already mangled into U+FFFD, so
    the GBK path must parse the query string itself."""
    for pair in query_string.split(b"&"):
        if pair.startswith(b"q="):
            return unquote_to_bytes(pair[2:].replace(b"+", b" "))
    return b""


@bp.route("/myteam")
def myteam():
    """Second-order demo: 'colleagues in my department', built from the current
    user's STORED status. The status was saved via a parameterized profile
    update (safe), but it is re-used here concatenated into the query (unsafe)."""
    user = g.get("session", {}).get("user")
    if not user:
        return redirect(url_for("auth.login"))
    conn = get_conn()
    try:
        status = get_user_status(conn, user["id"])     # safe parameterized read
        results, executed_sql = secondorder_lookup(conn, status)  # unsafe re-use
    finally:
        conn.close()
    return render_template("search.html", active_nav="directory", term="",
                           results=results, impl="second-order",
                           executed_sql=executed_sql)


@bp.route("/search")
def search():
    raw_term = request.args.get("q", "")
    impl = resolve("SQL_IMPL", request.args, Config.SQL_IMPL)
    rasp_mode = resolve("RASP_MODE", request.args, Config.RASP_MODE)
    serversan = request.args.get("serversan", "off").strip().lower()
    id_expr = request.args.get("id")
    sort = request.args.get("sort")

    # Charset-confusion path: needs the RAW request bytes (Flask already mangled
    # the 0xbf lead byte in raw_term) and its own GBK-charset connection. Handled
    # before the normal decoded-string flow because it works at the byte level.
    if impl == "gbk":
        conn = get_conn(charset="gbk")
        try:
            results, executed_sql = search_directory_gbk(
                conn, _raw_q_bytes(request.query_string), rasp_mode)
        except RaspBlocked as blocked:
            return _rasp_blocked_page(blocked.verdict)
        finally:
            conn.close()
        return render_template("search.html", active_nav="directory",
                               term=raw_term, results=results, impl=impl,
                               executed_sql=executed_sql)

    # Tier 1: server-side sanitization runs on the server (curl cannot skip it).
    term, rejected = purify_server(raw_term, serversan)

    results, executed_sql = [], None
    conn = get_conn()
    try:
        if rejected:
            executed_sql = "(input rejected by server-side allowlist)"
        elif id_expr is not None:
            id_clean, _ = purify_server(id_expr, serversan)
            results, executed_sql = filter_directory_by_id(conn, id_clean, rasp_mode)
        elif sort is not None:
            results, executed_sql = search_directory_param_sorted(conn, term, sort, rasp_mode)
        elif term:
            fn = SEARCH_IMPLS.get(impl, SEARCH_IMPLS["concat"])
            results, executed_sql = fn(conn, term, rasp_mode)
        else:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name, title, department, email, phone, location "
                    "FROM directory ORDER BY name LIMIT 100"
                )
                results = cur.fetchall()
    except RaspBlocked as blocked:
        return _rasp_blocked_page(blocked.verdict)
    finally:
        conn.close()

    return render_template(
        "search.html",
        active_nav="directory",
        term=raw_term,
        results=results,
        impl=impl,
        executed_sql=executed_sql,
    )
