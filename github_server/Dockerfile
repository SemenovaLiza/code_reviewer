FROM python:3.12-slim

WORKDIR /server

COPY requirements.webhook.txt .
RUN pip install --no-cache-dir -r requirements.webhook.txt

COPY server.py .

EXPOSE 8001

CMD ["python3", "server.py"]