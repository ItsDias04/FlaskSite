# Используем официальный образ Python в качестве базового
FROM python:3.9

# Устанавливаем зависимости
COPY requirements.txt .
RUN pip install -r requirements.txt

# Копируем файлы приложения
COPY . /flaskapp

# Устанавливаем рабочую директорию
WORKDIR /flaskapp

# Указываем команду для запуска приложения
CMD ["python", "main.py"]