import ldap

BASE = "ou=people,dc=example,dc=com"


def lookup(conn, username: str):
    return conn.search_s(BASE, ldap.SCOPE_SUBTREE, "(uid=" + username + ")")
