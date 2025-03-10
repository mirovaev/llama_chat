import os
import requests
import redis
import logging
import json
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-fixed-secret-key")

# Настройки сессий с использованием Redis
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"
app.config["SESSION_REDIS"] = redis.from_url(os.getenv("REDIS_URL"))
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

Session(app)

redis_client = redis.from_url(os.getenv("REDIS_URL"))

# API-ключ Together.ai (замени на свой)
API_KEY = "b1b8d176370c2e335662bf870ba959e9db1c9447702f2df1023e59fed0e5f3cd"
URL = "https://api.together.xyz/v1/chat/completions"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Требуется авторизация"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET"])
def login_page():
    if "user" in session:
        return redirect(url_for("index"))  # Если уже авторизован, перенаправляем на главную страницу
    return render_template("login.html")  # Показываем страницу логина

@app.route("/register", methods=["GET"])
def register_page():
    if "user" in session:
        return redirect(url_for("index"))  # Если уже авторизован, перенаправляем на главную страницу
    return render_template("register.html")  # Показываем страницу регистрации

# Регистрация пользователя
@app.route("/register_user", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return redirect(url_for("register_page"))  # Перенаправление на форму регистрации

    if not request.is_json:
        return jsonify({"error": "Ожидался JSON"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "Некорректный JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Введите логин и пароль"}), 400

    if redis_client.hexists("users", username):
        return jsonify({"error": "Пользователь уже существует"}), 400

    hashed_password = generate_password_hash(password)
    redis_client.hset("users", username, hashed_password)

    return jsonify({"message": "Пользователь зарегистрирован"})

# @app.before_request
# def check_auth():
#     print(f"Сессия перед запросом: {session}")
#     if request.endpoint not in ["login", "static", "register"]:
#         if not session.get("user"):
#             print("Не авторизован!")
#             return jsonify({"error": "Требуется авторизация"}), 401

@app.route("/login_user", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return redirect(url_for("login_page"))  # Перенаправление на форму логина

    try:
        if not request.is_json:
            return jsonify({"error": "Ожидался JSON"}), 400

        data = request.get_json()
        if not data:
            return jsonify({"error": "Некорректный JSON"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Введите логин и пароль"}), 400

        stored_password = redis_client.hget("users", username)

        if not stored_password:
            return jsonify({"error": "Неверный логин или пароль"}), 401

        if not check_password_hash(stored_password.decode('utf-8'), password):
            return jsonify({"error": "Неверный логин или пароль"}), 401

        session["user"] = username
        session.modified = True  # Принудительное сохранение сессии

        # Теперь корректно сохраняем список сообщений в Redis
        redis_client.set(f"user:{session['user']}:messages", json.dumps(session.get("messages", [])))

        return jsonify({"message": "Вход выполнен"})

    except Exception as e:
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500

# Выход пользователя
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    session.modified = True  # <-- Принудительное сохранение сессии
    return jsonify({"message": "Выход выполнен"})

# Проверка статуса сессии
@app.route("/status", methods=["GET"])
def status():
    session_id = request.cookies.get('session')

    if not session_id:
        return jsonify({'error': 'Authorization required'}), 401

    user = redis_client.get(f'session:{session_id}')

    if not user:
        return jsonify({'error': 'Invalid session'}), 401

    return jsonify({'message': f'Hello, {user.decode()}'})


@app.route("/")
def index():
    if "user" not in session:  # Проверяем, есть ли пользователь в сессии
        return redirect(url_for("login"))  # Если нет, отправляем на страницу логина

    # Если пользователь залогинен, проверяем, есть ли история сообщений
    if "messages" not in session:
        session["messages"] = [{"role": "system", "content": "Ты — полезный AI-ассистент."}]

    return render_template("index.html")

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json()

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

    try:
        response = requests.post(URL, json=payload, headers=headers)
        response.raise_for_status()  # Генерирует исключение для 4xx и 5xx ошибок
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Ошибка при взаимодействии с API"}), 500
        # Если запрос успешен, возвращаем ответ API
    reply = response.json()["choices"][0]["message"]["content"]
    session["messages"].append({"role": "assistant", "content": reply})
    return jsonify({"response": reply})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)