import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings
from langchain_core.tools import create_retriever_tool

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
            embedding=embeddings,
            collection_name=COLLECTION_NAME,
            path="./collections/qdrant_storage"
        )
    return store


def get_context(top_k=5):
    retriever = get_store().as_retriever(search_kwargs={'k': top_k})
    retriever_tool = create_retriever_tool(
        retriever, name='KEV_KB',
        description='Use when the user asks about known exploited vulnerabilities, whether a specific CVE is in the KEV catalog, remediation deadlines, which vendors or products are most targeted, or any question requiring up-to-date KEV data. Also trigger when the user asks to audit a list of CVEs against KEV, prioritize patching based on active exploitation, or export/filter KEV entries by date, severity, or product')
    return retriever_tool


def run_embeddings():
    docs = get_docs()

    if not docs:
        raise ValueError("No non-empty documents to embed")
    
    create_collection(docs)
    print('collection was created')

    print('embedded')


if __name__ == '__main__':
    run_embeddings()
