from flask import Flask

app = Flask(__name__)


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    return {"id": user_id}


@app.route("/api/users/<int:user_id>/avatar", methods=["POST"])
def upload_avatar(user_id):
    return {"ok": True}


@app.route("/api/reports", methods=["GET"])
def reports():
    return []


@app.route("/internal/debug", methods=["GET"])
def debug():
    return {}
