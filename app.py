import os
import redis
import logging
import json
import requests
from config import SYSTEM_PROMPT, ASSISTANT_GREETING  # Импортируем константы
from dotenv import load_dotenv
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

# Загружаем переменные из .env
load_dotenv()

print(os.getenv("REDIS_URL"))
REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    print("REDIS_URL is not set!")
else:
    print(f"REDIS_URL is: {REDIS_URL}")


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
API_KEY = os.getenv("API_KEY")
URL = os.getenv("URL")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

if not API_KEY or not URL:
    logger.error("API_KEY или URL не загружены! Проверь переменные окружения.")
    raise ValueError("Отсутствуют необходимые переменные окружения")

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


# @app.route("/")
# def index():
#     if "user" not in session:  # Проверяем, есть ли пользователь в сессии
#         return redirect(url_for("login"))  # Если нет, отправляем на страницу логина
#
#     # Если пользователь залогинен, проверяем, есть ли история сообщений
#     if "messages" not in session:
#         # Читаем системный промт из файла
#         system_prompt = read_system_prompt()
#         logger.debug(f"Системный промт: {system_prompt}")  # Отладочный лог
#         session["messages"] = [{"role": "system", "content": system_prompt}]
#
#     return render_template("index.html")

@app.route("/")
def index():
    if "user" not in session:  # Проверяем, есть ли пользователь в сессии
        return redirect(url_for("login"))  # Если нет, отправляем на страницу логина

    # Если пользователь залогинен, проверяем, есть ли история сообщений
    if "messages" not in session:
        # В случае отсутствия сообщений просто инициализируем пустой список сообщений
        session["messages"] = []

    return render_template("index.html")

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


def read_system_prompt():

    with open("system_prompt.txt", "r", encoding="utf-8") as file:
        return file.read().strip()  # Убираем возможные пробелы в начале и конце


@app.route("/init_chat", methods=["GET"])
@login_required
def init_chat():
    if "messages" not in session:
        session["messages"] = [{"role": "assistant", "content": "Привет, я ИИ помощник по подбору цветов, чем могу быть полезен?"}]
    return jsonify({"response": session["messages"][-1]["content"]})


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"error": "Некорректный JSON"}), 400

    user_input = data["message"].strip()
    if not user_input:
        return jsonify({"error": "Пустой запрос"}), 400


    # # Если сессия не содержит сообщений, добавляем приветственное сообщение от ассистента
    # if "messages" not in session:
    #     session["messages"] = [
    #         {"role": "assistant", "content": "Привет, я ИИ помощник по подбору цветов, чем могу быть полезен?"}]
    #
    #     # Добавление сообщения пользователя
    # session["messages"].append({"role": "user", "content": user_input})
    #
    # # Если после приветствия поступил первый запрос, добавляем системный промт
    # if len(session["messages"]) == 2:  # Приветствие + сообщение пользователя
    #     system_prompt = read_system_prompt()
    #     session["messages"].append({"role": "assistant", "content": system_prompt})
    #
    # logger.debug(f"Текущие сообщения: {session['messages']}")

    # Добавление сообщения пользователя
    session["messages"].append({"role": "user", "content": user_input})

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama3.1:8b",
        "messages": session["messages"],
        "max_tokens": 200,
        "temperature": 0.7
    }

    try:
        response = requests.post(URL, json=payload, headers=headers)
        response.raise_for_status()  # Генерирует исключение для 4xx и 5xx ошибок
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Ошибка при взаимодействии с API"}), 500

    reply = response.json()["choices"][0]["message"]["content"]
    session["messages"].append({"role": "assistant", "content": reply})

    # Если сгенерировала заказ или подтвердила его, отправляем уведомление в Telegram
    if "Новый заказ!" in reply or "Заказ подтвержден!" in reply:
        send_to_telegram(reply)

    return jsonify({"response": reply})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)