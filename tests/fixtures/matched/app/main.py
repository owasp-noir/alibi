from flask import Flask, request

app = Flask(__name__)


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    return {"id": user_id}


@app.route("/users/<int:user_id>/avatar", methods=["POST"])
def upload_avatar(user_id):
    return {"ok": True}


@app.route("/internal/metrics", methods=["GET"])
def metrics():
    return {"uptime": 1}
