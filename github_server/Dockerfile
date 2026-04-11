FROM python:3.12-slim

WORKDIR /server

COPY github_server/requirements.webhook.txt .

RUN pip install --no-cache-dir -r requirements.webhook.txt

COPY github_server/server.py .

EXPOSE 8001

CMD ["python3", "server.py"]
