import os
from dotenv import load_dotenv
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings
from langchain_core.tools import create_retriever_tool
from qdrant_client.models import Filter, FieldCondition, MatchValue, MatchAny

from preprocessing import cwe_documents, run_dependency_check


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
        This knowledge base contains CWE (Common Weakness Enumeration) entries describing code-level security weaknesses. Use it to identify and classify vulnerabilities found in code during security analysis.
        Query this knowledge base when you encounter a code construct that may introduce a security risk — such as unsanitized input, unsafe file handling, hardcoded secrets, insecure cryptography, or improper access control. Match the construct against the most specific CWE entry available. Draw all mitigation recommendations directly from the matched entry's potential_mitigations field, adapted to the specific vulnerable code. Do not report a finding if no matching CWE entry exists in this knowledge base.
        """
    )
    return retriever_tool


def get_dependecy_cwe(cwe_ids, top_k: int = 3):
    qdrant_client = get_store().client

    results, _ = qdrant_client.scroll(
        collection_name=COLLECTION_NAME,
        scroll_filter=Filter(
            must=[
                FieldCondition(key="metadata.cweID", match=MatchAny(any=cwe_ids))
            ]
        ),
        with_payload=True,
        with_vectors=False
    )
    
    return results


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
    result = get_dependecy_cwe(run_dependency_check())

    print('embedded')
    print(result)


if __name__ == '__main__':
    run_embeddings()
    # debug_retrieval("Improper Neutralization of Special Elements Used in a Template Engine")

