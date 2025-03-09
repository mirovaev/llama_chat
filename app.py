import os
import requests
import redis
from flask import Flask, render_template, request, jsonify, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Или задайте свой ключ

# Настройки сессий с использованием Redis
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"
app.config["SESSION_REDIS"] = redis.from_url(os.getenv("REDIS_URL"))

Session(app)
r = redis.Redis.from_url(os.getenv("REDIS_URL"))


# Регистрация пользователя
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Введите логин и пароль"}), 400

    if r.hexists("users", username):
        return jsonify({"error": "Пользователь уже существует"}), 400

    hashed_password = generate_password_hash(password)
    r.hset("users", username, hashed_password)
    return jsonify({"message": "Пользователь зарегистрирован"})


# Вход пользователя
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Введите логин и пароль"}), 400

    stored_password = r.hget("users", username)
    if not stored_password or not check_password_hash(stored_password.decode(), password):
        return jsonify({"error": "Неверный логин или пароль"}), 401

    session["user"] = username
    return jsonify({"message": "Вход выполнен"})


# Выход пользователя
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"message": "Выход выполнен"})


# Проверка статуса сессии
@app.route("/status", methods=["GET"])
def status():
    if "user" in session:
        return jsonify({"message": f"Вы вошли как {session['user']}"})
    return jsonify({"message": "Вы не авторизованы"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)
