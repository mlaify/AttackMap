# #242: @login_required proves the caller is logged in, not that the order is
# theirs. The order is fetched by id with no ownership check.
from flask import Flask, jsonify
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = db.session.get(Order, order_id)
    app.logger.info("order %s viewed by %s", order_id, current_user.email)
    return jsonify(order.to_dict())
