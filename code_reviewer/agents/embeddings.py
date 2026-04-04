import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings
from langchain_core.tools import create_retriever_tool

from preprocessing import cwe_documents


load_dotenv()

VOYAGE_API_KEY = os.getenv('VOYAGE_API_KEY')
COLLECTION_NAME= os.getenv('COLLECTION_NAME')
EMBED_MODEL = os.getenv('EMBED_MODEL')


embeddings = MistralAIEmbeddings(
    model=EMBED_MODEL,
)

store = None


def get_docs():
    return cwe_documents()


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
    retriever,
    name='KEV_KB',
    description="""
        Use ONLY when you have a specific product name or library name to look up.
        Examples of good queries: "SAP NetWeaver", "Citrix ADC", "Apache Log4j", "sqlite3 npm".
        
        Do NOT use for generic code patterns like SQL injection, path traversal, 
        hardcoded secrets, or auth issues found in custom application code.
        Those should be mapped to CWE IDs, not CVEs.
        """
    )
    return retriever_tool


def debug_retrieval(query: str, top_k: int = 5):
    store = get_store()
    results = store.similarity_search_with_score(query, k=top_k)
    
    for i, (doc, score) in enumerate(results):
        print(f"\n--- Chunk {i+1} | Score: {score:.4f} ---")
        print(f"Metadata: {doc.metadata}")
        print(f"Content: {doc.page_content}")
        print("-" * 60)



def run_embeddings():
    docs = get_docs()

    if not docs:
        raise ValueError("No non-empty documents to embed")
    
    create_collection(docs)
    print('collection was created')

    print('embedded')


if __name__ == '__main__':
    #run_embeddings()
    debug_retrieval("User input is rendered in HTML without escaping")

