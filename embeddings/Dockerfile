FROM python:3.12-slim

WORKDIR /embeddings

COPY requirements.embeddings.txt .
RUN pip install --no-cache-dir -r requirements.embeddings.txt

COPY shared/ ./shared/

COPY embeddings/ ./embeddings/

EXPOSE 6333

CMD ["python3", "embeddings/main.py"]