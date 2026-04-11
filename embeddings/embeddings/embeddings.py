import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings

from preprocessing import cwe_documents
from shared.store import embeddings, EMBED_MODEL, QDRANT_URL, COLLECTION_NAME


load_dotenv()

VOYAGE_API_KEY = os.getenv('VOYAGE_API_KEY')


def get_docs():
    return cwe_documents()


def create_collection(docs, embeddings=embeddings, collection_name=COLLECTION_NAME):
    QdrantVectorStore.from_documents(
        documents=docs,
        embedding=embeddings,
        # path="./collections/qdrant_storage",
        url=QDRANT_URL,
        collection_name=collection_name
    )


# def dependency_vulnerability_analysis(_:str = ""):
#     print("TOOL CALLED: investigate_vulnerabilities")
#     cwe_ids = run_dependency_check()
#     qdrant_client = get_store().client

#     results, _ = qdrant_client.scroll(
#         collection_name=COLLECTION_NAME,
#         scroll_filter=Filter(
#             must=[
#                 FieldCondition(key="metadata.cweID", match=MatchAny(any=cwe_ids))
#             ]
#         ),
#         with_payload=True,
#         with_vectors=False
#     )
#     print(results)
#     message = f"Known dependency CWEs: {results}"
#     return message

# def debug_retrieval(query: str, top_k: int = 5):
#     store = get_store()
#     results = store.similarity_search_with_score(query, k=top_k)
    
#     for i, (doc, score) in enumerate(results):
#         print(f"\n--- Chunk {i+1} | Score: {score:.4f} ---")
#         print(f"Metadata: {doc.metadata}")
#         print(f"Content: {doc.page_content}")
#         print("-" * 60)


def run_embeddings():
    from qdrant_client import QdrantClient
    client = QdrantClient(url=QDRANT_URL)
    
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME in existing:
        print(f"Collection '{COLLECTION_NAME}' already exists, skipping ingestion.")
        return

    docs = get_docs()
    if not docs:
        raise ValueError("No documents to embed")
    create_collection(docs)
    print("Collection created.")


if __name__ == '__main__':
    run_embeddings()
    # debug_retrieval("Improper Neutralization of Special Elements Used in a Template Engine")

