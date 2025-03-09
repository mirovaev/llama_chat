import os
import requests
import redis
from flask import Flask, render_template, request, jsonify, session
from flask_session import Session

app = Flask(__name__)
app.secret_key = os.urandom(24)  # или задайте свой ключ

# Настройки сессий с использованием Redis
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"
app.config["SESSION_REDIS"] = redis.from_url(os.getenv("REDIS_URL"))

Session(app)

# API-ключ Together.ai (замени на свой)
API_KEY = "b1b8d176370c2e335662bf870ba959e9db1c9447702f2df1023e59fed0e5f3cd"
URL = "https://api.together.xyz/v1/chat/completions"

# @app.route("/")
# def index():
#     session["messages"] = session.get("messages", [{"role": "system", "content": "Ты — полезный AI-ассистент."}])
#     return render_template("index.html")

@app.route("/")
def index():
    if "messages" not in session:
        session["messages"] = [{"role": "system", "content": "Ты — полезный AI-ассистент."}]
    return render_template("index.html")

# код для проверки корректной работы редиса
@app.route("/check-redis")
def check_redis():
    try:
        r = redis.Redis.from_url(os.getenv("REDIS_URL"))
        r.set("test_key", "test_value")
        return "Redis is working"
    except Exception as e:
        return f"Redis connection failed: {e}"


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    print("📥 Полученные данные:", data)

    if not data or "message" not in data:
        return jsonify({"error": "Некорректный JSON"}), 400

    user_input = data["message"].strip()
    if not user_input:
        return jsonify({"error": "Пустой запрос"}), 400

    # Используем сессию вместо глобальной переменной messages
    session["messages"].append({"role": "user", "content": user_input})

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo-p",
        "messages": session["messages"],
        "max_tokens": 200,
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