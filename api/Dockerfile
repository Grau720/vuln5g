FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ya no necesitas copiar nada porque los volúmenes lo harán
# Pero dejamos esto por si ejecutas sin docker-compose
COPY api/ ./api/
COPY services/ ./services/

ENV PYTHONPATH=/app

EXPOSE 5000
CMD ["python", "api/app.py"]