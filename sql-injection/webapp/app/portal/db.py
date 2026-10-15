"""Thin MySQL access layer for the data tier.

Two things live here on purpose:

  * ``get_conn`` -- a per-request PyMySQL connection to the ``db`` container.
  * The two SQL *paths* the SQLi scenario contrasts: a string-concatenated query
    (vulnerable) and a parameterized query (safe). Both are reached through the
    same route; a toggle selects which one runs, so the only difference between
    an attack and its benign twin is whether the concatenated path parses the
    input as structure or as data.
"""
import pymysql

from .config import Config


def get_conn(charset: str = "utf8mb4"):
    """Per-request PyMySQL connection. ``charset`` is overridable only so the
    charset-confusion path (``search_directory_gbk``) can open a GBK connection;
    every normal path uses the utf8mb4 default."""
    return pymysql.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        charset=charset,
    )


# --- Directory search -------------------------------------------------------
# The SQLi anchor. Same user action, two implementations behind a flag.

_DIR_COLS = "id, name, title, department, email, phone, location"


def search_directory_concat(conn, term: str):
    """VULNERABLE: the term is concatenated straight into the SQL text, so an
    input like  ' OR '1'='1  adds a new logical clause to the parse tree."""
    sql = (
        "SELECT " + _DIR_COLS + " FROM directory "
        "WHERE name LIKE '%" + term + "%' ORDER BY name LIMIT 50"
    )
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall(), sql


def search_directory_param(conn, term: str):
    """SAFE: the term is bound as a value; the query's structure is fixed."""
    sql = (
        "SELECT " + _DIR_COLS + " FROM directory "
        "WHERE name LIKE %s ORDER BY name LIMIT 50"
    )
    with conn.cursor() as cur:
        cur.execute(sql, ("%" + term + "%",))
        return cur.fetchall(), sql


def _naive_byte_escape(raw: bytes) -> bytes:
    """A deliberately broken, charset-UNAWARE escaper -- the kind a hand-rolled
    ``addslashes()`` is. It walks the RAW BYTES and prepends a backslash (0x5c)
    before every quote/backslash byte, with no idea whether a byte starts a
    multibyte character. That ignorance is the whole bug: under a GBK connection a
    lead byte like 0xbf swallows the 0x5c we just inserted as the second half of a
    2-byte character, so the 0x27 quote it was meant to neutralise is set free.
    A charset-AWARE escaper (what PyMySQL's parameter binding does) would see the
    0xbf opening a 2-byte char and never treat the next byte as a lone quote."""
    out = bytearray()
    for b in raw:
        if b in (0x27, 0x22, 0x5c):  # ' " \
            out.append(0x5c)
        out.append(b)
    return bytes(out)


def search_directory_gbk(conn, term_bytes: bytes):
    """CHARSET-CONFUSION sink (sqli-reference: encoding/charset confusion). The
    term is escaped on the raw BYTES by ``_naive_byte_escape`` and only then
    interpreted as GBK -- the escape and the charset decode disagree about where
    character boundaries are. Feed it ``%bf%27 OR 1=1-- -`` and the escaper turns
    0xbf 0x27 into 0xbf 0x5c 0x27; GBK reads 0xbf5c as one character, leaving a
    live quote that breaks out into the parse tree.

    This is the ONE place in the lab where 'but we escape quotes' is actually
    defeated. Contrast ``search_directory_concat`` (no escaping, trivially
    injectable) and ``search_directory_param`` -- the parameterized path is immune
    here too, because PyMySQL escapes per decoded character, never byte-wise, so
    the GBK trick has nothing to confuse. ``conn`` MUST be a GBK connection
    (``get_conn(charset="gbk")``)."""
    escaped = _naive_byte_escape(term_bytes)
    term = escaped.decode("gbk", errors="replace")
    sql = (
        "SELECT " + _DIR_COLS + " FROM directory "
        "WHERE name LIKE '%" + term + "%' ORDER BY name LIMIT 50"
    )
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall(), sql


def search_directory_proc(conn, term: str):
    """Tier 2 hole: a STORED PROCEDURE that builds dynamic SQL from its parameter.
    The term is passed bound (looks safe) but the proc CONCATs it into the query,
    so injection lands inside the procedure. 'We use stored procedures' != safe."""
    with conn.cursor() as cur:
        cur.callproc("search_dir", (term,))
        return cur.fetchall(), "CALL search_dir(%s)  -- proc concatenates term into dynamic SQL"


def get_user_status(conn, uid):
    """SAFE parameterized read of a user's own stored status."""
    with conn.cursor() as cur:
        cur.execute("SELECT status FROM users WHERE id = %s", (uid,))
        row = cur.fetchone()
    return (row or {}).get("status") or ""


def secondorder_lookup(conn, status: str):
    """SECOND-ORDER sink. The status was STORED earlier via a parameterized query
    (safe at entry), but here it is read back and CONCATENATED into a new query
    (unsafe at use). Input-time parameterization does not help -- the injection
    is re-introduced from storage."""
    sql = (
        "SELECT " + _DIR_COLS + " FROM directory "
        "WHERE department LIKE '%" + status + "%' ORDER BY name LIMIT 50"
    )
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall(), sql


def filter_directory_by_id(conn, id_expr: str):
    """Tier 1 numeric-context: id is concatenated WITHOUT quotes, so a
    quote-escaping sanitizer has nothing to escape."""
    sql = (
        "SELECT " + _DIR_COLS + " FROM directory "
        "WHERE id = " + id_expr + " ORDER BY name LIMIT 50"
    )
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchall(), sql


def search_directory_param_sorted(conn, term: str, sort: str):
    """Tier 2 hole: the VALUE is parameterized (safe), but the ORDER BY column is
    an IDENTIFIER, which cannot be parameterized, so it is concatenated. Injection
    returns through the sort parameter despite 'using prepared statements'."""
    sql = (
        "SELECT " + _DIR_COLS + " FROM directory "
        "WHERE name LIKE %s ORDER BY " + sort + " LIMIT 50"
    )
    with conn.cursor() as cur:
        cur.execute(sql, ("%" + term + "%",))
        return cur.fetchall(), sql


# --- Login ------------------------------------------------------------------
# The login route also reaches the DB and shares the same two-path design.

def login_concat(conn, username: str, password: str):
    """VULNERABLE: classic auth-bypass surface (' OR '1'='1' -- )."""
    sql = (
        "SELECT id, username, display_name, bio, homepage FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    with conn.cursor() as cur:
        cur.execute(sql)
        return cur.fetchone(), sql


def login_param(conn, username: str, password: str):
    """SAFE: credentials bound as values."""
    sql = (
        "SELECT id, username, display_name, bio, homepage FROM users "
        "WHERE username = %s AND password = %s"
    )
    with conn.cursor() as cur:
        cur.execute(sql, (username, password))
        return cur.fetchone(), sql


# Dispatch helpers keyed by the resolved SQL_IMPL toggle.
SEARCH_IMPLS = {
    "concat": search_directory_concat,
    "param": search_directory_param,
    "proc": search_directory_proc,
}
LOGIN_IMPLS = {"concat": login_concat, "param": login_param}
