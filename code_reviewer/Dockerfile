FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/

COPY code_review/ ./code_review/

CMD ["python", "code_review/main"]