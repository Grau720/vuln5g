FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

COPY ../../requirements.txt .
COPY ../../.env .

RUN pip install --no-cache-dir -r requirements.txt

COPY ../../config ./config
COPY ../../scripts ./scripts
COPY ../../services ./services
COPY ../../data ./data

CMD ["python", "scripts/ingest.py"]
