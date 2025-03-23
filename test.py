# # Инициализация списка сообщений, если он еще не создан. тут должен быть систем промт
# if "messages" not in session:
#     system_prompt = read_system_prompt()  # Читаем системный промт из
#     # ASSISTANT_GREETING = "Привет, я ИИ помощник по подбору цветов, чем могу быть полезен?"
#     session["messages"] = [
#
#          # {"role": "assistant", "content": "ПРивет, я ИИ помощник по подбору цветов, чем могу быть полезен?"},
#         {"role": "user", "content": user_input},
#         {"role": "assistant", "content": system_prompt},
#         # {"role": "system", "content": system_prompt},
#     ]
#     session["messages"].append({"role": "user", "content": user_input})

# # Если сессия не содержит сообщений, добавляем приветственное сообщение от бота
# if "messages" not in session:
#     session["messages"] = [{"role": "assistant", "content": "Привет, я ИИ помощник по подбору цветов, чем могу быть полезен?"}]

# # Если в сессии только приветственное сообщение, добавляем системный промт
# if len(session["messages"]) == 1:  # Только приветствие
#     system_prompt = read_system_prompt()
#     session["messages"].append({"role": "assistant", "content": system_prompt},
#                                session["messages"].append({"role": "user", "content": user_input})
#                                )
#
# logger.debug(f"Текущие сообщения: {session['messages']}")

