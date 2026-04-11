FROM python:3.12-slim

WORKDIR /embeddings

COPY embeddings/requirements.embeddings.txt .

RUN pip install --no-cache-dir -r requirements.embeddings.txt

COPY shared/ ./shared/

COPY embeddings/embeddings/ ./embeddings/

ENV PYTHONPATH=/embeddings

CMD ["python3", "embeddings/embeddings.py"]
