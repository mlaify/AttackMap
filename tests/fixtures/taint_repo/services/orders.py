from db.orders import fetch_order


def place_order(order_id):
    row = fetch_order(order_id)
    return {"ok": True, "row": row}
