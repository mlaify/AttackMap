import sqlite3

_conn = sqlite3.connect(":memory:")


def fetch_order(order_id):
    cursor = _conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id={order_id}")
    return cursor.fetchone()
