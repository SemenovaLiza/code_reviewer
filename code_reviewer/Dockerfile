FROM python:3.12-slim

WORKDIR /app

COPY code_reviewer/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/

COPY code_reviewer/code_review/ ./code_review/

ENV PYTHONPATH=/app

CMD ["python", "code_review/main.py"]
