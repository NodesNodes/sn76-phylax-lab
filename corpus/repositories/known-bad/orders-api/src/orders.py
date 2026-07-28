import sqlite3


def connect():
    return sqlite3.connect("orders.db")


def find(conn, customer):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE customer = '{customer}'")
    return cur.fetchall()
