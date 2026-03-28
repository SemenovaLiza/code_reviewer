import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams
from langchain_voyageai import VoyageAIEmbeddings

from preprocessing import docs


load_dotenv()


VOYAGE_API_KEY = os.getenv('VOYAGE_API_KEY')

if __name__ == '__main__':

    collection_name = "cve_collection"

    embed_model = VoyageAIEmbeddings(
        voyage_api_key=VOYAGE_API_KEY,
        model="voyage-law-2"
    )
    print('imported voyage')

    print('embedded')
    vectore_store = QdrantVectorStore.from_documents(
        docs,
        embedding=embed_model,
        path="./langchain_qdrant",
        collection_name=collection_name,
    )
    print('vector store created')
