import os
import requests
import redis
from flask import Flask, render_template, request, jsonify, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-fixed-secret-key")

# Настройки сессий с использованием Redis
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"
app.config["SESSION_REDIS"] = redis.from_url(os.getenv("REDIS_URL"))

Session(app)
r = redis.Redis.from_url(os.getenv("REDIS_URL"))

# API-ключ Together.ai (замени на свой)
API_KEY = "b1b8d176370c2e335662bf870ba959e9db1c9447702f2df1023e59fed0e5f3cd"
URL = "https://api.together.xyz/v1/chat/completions"


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



@app.route("/")
def index():
    if "messages" not in session:
        session["messages"] = [{"role": "system", "content": "Ты — полезный AI-ассистент."}]
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    print("📥 Полученные данные:", data)

    if not data or "message" not in data:
        return jsonify({"error": "Некорректный JSON"}), 400

    user_input = data["message"].strip()
    if not user_input:
        return jsonify({"error": "Пустой запрос"}), 400

    # Инициализация сессии, если её нет
    if "messages" not in session:
        session["messages"] = [{"role": "system", "content": "Ты — полезный AI-ассистент."}]

    # Добавление сообщения пользователя
    session["messages"].append({"role": "user", "content": user_input})

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo-p",
        "messages": session["messages"],
        "max_tokens": 500,
        "temperature": 0.7
    }

    response = requests.post(URL, json=payload, headers=headers)

    if response.status_code == 200:
        reply = response.json()["choices"][0]["message"]["content"]
        session["messages"].append({"role": "assistant", "content": reply})
        return jsonify({"response": reply})
    else:
        print("❌ Ошибка API:", response.text)
        return jsonify({"error": f"Ошибка API: {response.text}"}), response.status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)