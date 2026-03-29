import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings

from preprocessing import json_to_txt


load_dotenv()

VOYAGE_API_KEY = os.getenv('VOYAGE_API_KEY')
COLLECTION_NAME= os.getenv('COLLECTION_NAME')
EMBED_MODEL = os.getenv('EMBED_MODEL')


embeddings = MistralAIEmbeddings(
    model=EMBED_MODEL,
)

store = None


def get_docs():
    return json_to_txt()


def create_collection(docs, embeddings=embeddings, collection_name=COLLECTION_NAME):
    QdrantVectorStore.from_documents(
        documents=docs,
        embedding=embeddings,
        path="./collections/qdrant_storage",
        collection_name=collection_name
    )


def get_store():
    global store
    if store is None:
        store = QdrantVectorStore.from_existing_collection(
            embeddings=embeddings,
            collection_name=COLLECTION_NAME,
            path="./collections/qdrant_storage"
        )
    return store


def get_context(query, top_k=5):
    result = get_store().similarity_search(query, k=top_k)
    return result


def run_embeddings():
    docs = get_docs()

    if not docs:
        raise ValueError("No non-empty documents to embed")
    
    create_collection(docs)
    print('collection was created')

    print('embedded')


if __name__ == '__main__':
    run_embeddings()
