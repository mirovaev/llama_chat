import os
import redis
import logging
import json
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

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

API_KEY = "sk-PxEPRj0GrnGxNGmgnlufcxYEm277BCyl"
URL = "http://o10.ai.2mx.dev/v1/chat/completions"

# Токен Telegram-бота
TELEGRAM_BOT_TOKEN = '7905406053:AAHHyn4jc1Enk5txFE9ONwowgN9-6OGApig'
CHAT_ID = '456034821'


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
        # redis_client.set(f"user:{username}:session", session.sid)  # Привязка сессии к пользователю
        redis_client.set(f"session:{session.sid}", json.dumps(session))

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

def load_system_prompt():
    try:
        with open("system_prompt.txt", "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Ошибка при загрузке системного промта: {e}")
        return None

# Обработчик чата
@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")
    logger.debug(f"Получено сообщение от пользователя: {user_input}")

    # Инициализация списка сообщений, если он еще не создан
    if "messages" not in session:
        session["messages"] = [{"role": "system", "content": "Ты — полезный AI-ассистент."}]

    logger.debug(f"Текущие сообщения: {session['messages']}")
    session["messages"].append({"role": "user", "content": user_input})

    # Шаг 1: Проверка наличия имени пользователя и запоминание его
    def get_user_name():
        return session.get("user_name")

    def set_user_name(name):
        session["user_name"] = name

    # Шаг 2: Проверка наличия активного заказа и предоставление статуса или предложение нового заказа
    def check_order_status(order_id):
        return "Ваш заказ находится в обработке."

    def provide_order_status_or_new_order():
        if session.get("completed"):
            reply = "Спасибо за заказ! Если вам нужно что-то ещё, просто напишите мне."
        else:
            reply = f"Привет, {session['user_name']}! У вас есть активный заказ. Хотите узнать статус или оформить новый?"
        session["messages"].append({"role": "assistant", "content": reply})

    # Шаг 3: Пошаговое задание вопросов для сбора данных заказа
    def handle_order_step(step):
        logger.debug(f"Обрабатываем шаг: {step}")
        if step == 1:
            reply = "Как вас зовут?"
        elif step == 2:
            reply = "Выберите цветы для букета: классический романтик, весёлая ода или современная композиция?"
        elif step == 3:
            reply = "Введите информацию для оформления заказа (например, дополнительные детали: украшения, персонализированные записи)."
        elif step == 4:
            reply = "Введите дату доставки (гггг-мм-дд)."
        elif step == 5:
            reply = "Введите адрес доставки."
        else:
            reply = "Некорректный шаг."

        logger.debug(f"Ответ на шаг {step}: {reply}")
        session["messages"].append({"role": "assistant", "content": reply})

    # Шаг 4: Сохранение данных заказа
    def save_order_data(step, data):
        logger.debug(f"Сохраняем данные для шага {step}: {data}")
        if step == 1:
            set_user_name(data)
        elif step == 2:
            session["flowers"] = data
        elif step == 3:
            session["details"] = data
        elif step == 4:
            session["delivery_date"] = data
        elif step == 5:
            session["delivery_address"] = data

    # Шаг 5: Создание заказа и отправка в Telegram
    def create_order():
        order_data = {
            "user_name": session.get("user_name"),
            "flowers": session.get("flowers"),
            "details": session.get("details"),
            "delivery_date": session.get("delivery_date"),
            "delivery_address": session.get("delivery_address")
        }
        send_to_telegram(order_data)  # Ваша функция для отправки заказа в Telegram
        reply = "Заказ успешно оформлен!"
        session["messages"].append({"role": "assistant", "content": reply})
        session.pop("completed", None)

    # Основная логика обработчика чата
    try:
        if not get_user_name():
            set_user_name(user_input)
            handle_order_step(1)  # Начать с первого шага
        else:
            if user_input.isdigit() and int(user_input) in range(1, 6):
                step = int(user_input)
                handle_order_step(step)
            elif session.get("order_step"):
                step = session["order_step"]
                save_order_data(step, user_input)
                session["order_step"] += 1
                if step == 5:
                    create_order()
                else:
                    handle_order_step(session["order_step"])
            else:
                provide_order_status_or_new_order()

    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500

    return jsonify({"message": "Принято"})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)