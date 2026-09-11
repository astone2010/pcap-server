FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    openssh-client \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false -u 1000 -m appuser

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/ssh-keys /app/captures /app/data \
    && chown -R appuser:appuser /app/ssh-keys /app/captures /app/data

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
