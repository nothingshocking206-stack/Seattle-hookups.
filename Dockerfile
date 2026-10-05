# Single-container image: FastAPI + SQLite + static frontend.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/app.db \
    UPLOAD_DIR=/data/uploads \
    COOKIE_SECURE=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY static ./static

# /data holds the SQLite DB + uploads. Mount a persistent volume here
# (Render disk / Fly volume / Railway volume) or data is lost on redeploy.
VOLUME ["/data"]

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
