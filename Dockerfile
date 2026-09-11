FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

RUN mkdir -p /app/ssh-keys /app/captures /app/data

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
