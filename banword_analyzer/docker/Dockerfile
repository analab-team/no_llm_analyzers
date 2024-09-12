FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements /app/requirements

RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements/production.txt

COPY ./app /app
COPY ./.env /.env

EXPOSE 5061

# Команда запуска по умолчанию
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5061"]
