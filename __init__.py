from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Импортируем модели
from .models import User