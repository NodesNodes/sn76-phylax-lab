import ldap
from ldap.filter import escape_filter_chars

BASE = "ou=people,dc=example,dc=com"


def lookup(conn, username: str):
    filt = "(uid=%s)" % escape_filter_chars(username)
    return conn.search_s(BASE, ldap.SCOPE_SUBTREE, filt)
