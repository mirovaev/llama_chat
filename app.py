import os
import redis
import logging
import json
from config import SYSTEM_PROMPT, ASSISTANT_GREETING  # Импортируем константы
from dotenv import load_dotenv
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
# Загружаем переменные из .env
load_dotenv()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

# Используем их в коде
API_KEY = os.getenv("API_KEY")
URL = os.getenv("URL")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")


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

        # Сохраняем сессию в Redis по пользователю
        redis_client.set(f"user:{username}:session", session.sid)  # Привязка сессии к пользователю
        # redis_client.set(f"session:{session.sid}", json.dumps(session))

        # Теперь корректно сохраняем список сообщений в Redis
        redis_client.set(f"user:{session['user']}:messages", json.dumps(session.get("messages", [])))

        return jsonify({"message": "Вход выполнен"})

    except Exception as e:
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500


# Выход пользователя
@app.route("/logout", methods=["POST"])
def logout():
    username = session.get('user')

    if username:
        # Удаляем сессионные данные для пользователя из Redis
        redis_client.delete(f"user:{username}:session")
        redis_client.delete(f"user:{username}:messages")

    session.clear()
    session.modified = True  # Принудительное сохранение сессии
    return jsonify({"message": "Выход выполнен"})


@app.route("/status", methods=["GET"])
def status():
    username = session.get('user')

    if not username:
        return jsonify({'error': 'Authorization required'}), 401

    # Получаем идентификатор сессии для пользователя из Redis
    session_id = redis_client.get(f"user:{username}:session")

    if not session_id:
        return jsonify({'error': 'Invalid session'}), 401

    return jsonify({'message': f'Hello, {username}'})


@app.route("/")
def index():
    if "user" not in session:  # Проверяем, есть ли пользователь в сессии
        return redirect(url_for("login"))  # Если нет, отправляем на страницу логина

    # Если пользователь залогинен, проверяем, есть ли история сообщений
    if "messages" not in session:
        session["messages"] = [{"role": "system", "content": "Ты — полезный AI-ассистент."}]

    return render_template("index.html")


import requests


def send_to_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }

    try:
        response = requests.post(url, json=payload)
        # Логируем успешный ответ
        if response.status_code == 200:
            print(f"Message sent successfully: {response.json()}")
        else:
            print(f"Failed to send message: {response.status_code} - {response.text}")
        response.raise_for_status()  # Это также выбросит исключение в случае ошибки
    except requests.exceptions.RequestException as e:
        print(f"Error sending message: {e}")

# def load_system_prompt():
#     try:
#         with open("system_prompt.txt", "r", encoding="utf-8") as f:
#             return f.read()
#     except Exception as e:
#         logging.error(f"Ошибка при загрузке системного промта: {e}")
#         return None

# Читаем системный промт из файла
def read_system_prompt():
    with open("system_prompt.txt", "r", encoding="utf-8") as file:
        return file.read().strip()  # Убираем лишние пробелы и символы новой строки

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")
    logger.debug(f"Получено сообщение от пользователя: {user_input}")

    # Инициализация списка сообщений, если он еще не создан. тут должен быть систем промт
    if "messages" not in session:
        system_prompt = read_system_prompt()  # Читаем системный промт из файла
        session["messages"] = [
            {"role": "system", "content": system_prompt},
            {"role": "assistant", "content": ASSISTANT_GREETING}
        ]
    session["messages"].append({"role": "user", "content": user_input})
    logger.debug(f"Текущие сообщения: {session['messages']}")

    # Отправляем запрос к API нейросети
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama3.1:8b",
        "messages": session["messages"],
        "max_tokens": 500,
        "temperature": 0.7
    }

    response = requests.post(URL, json=payload, headers=headers)

    if response.status_code == 200:
        assistant_reply = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")

        # Сохраняем ответ нейросети в сессии
        session["messages"].append({"role": "assistant", "content": assistant_reply})
        session.modified = True  # Обновляем сессию

        return {"reply": assistant_reply}
    else:
        return {"error": "Ошибка при запросе к нейросети"}, 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)