import os
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings

COLLECTION_NAME = os.getenv('COLLECTION_NAME')
QDRANT_URL = os.getenv('QDRANT_URL', '')
embeddings = MistralAIEmbeddings(model=os.getenv('EMBED_MODEL'))
store = None

def get_store():
    global store
    if store is None:
        store = QdrantVectorStore.from_existing_collection(
            embedding=embeddings,
            collection_name=COLLECTION_NAME,
            url=QDRANT_URL
        )
    return store