FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -r -u 10001 mlsvc
USER mlsvc
EXPOSE 8100
# Один процесс: CatBoost сам использует все ядра при инференсе. Масштабирование — репликами сервиса.
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8100", "--no-access-log"]
