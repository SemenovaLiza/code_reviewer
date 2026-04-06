from qdrant_client.models import Filter, FieldCondition, MatchAny
from langchain_core.tools import create_retriever_tool
from langchain.tools import tool

from agents.embeddings import get_store, COLLECTION_NAME
from agents.preprocessing import run_dependency_check


@tool('investigate_dependency_vulnerabilities', description='''
        Use this tool to check project dependencies for known security vulnerabilities.
        It returns verified CWE data from authoritative sources.
        Call this tool when you need to identify vulnerabilities in third-party libraries.
        Do not use it for analyzing custom code.'''
)
def dependency_vulnerability_analysis(_:str = ""):
    print("TOOL CALLED: investigate_vulnerabilities")
    cwe_ids = run_dependency_check()
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
    message = f"Known dependency CWEs: {results}"
    return message


@tool('map_vulnerabilities_to_cwe', description='''
        Call this tool once after listing all detected vulnerabilities.
        Pass all vulnerabilities together as input.
        The tool returns authoritative CWE mappings and mitigation data.
        Use the returned results directly.
        The mapping is complete and does not require additional retrieval.'''
)
def map_vulnerabilities_to_cwe(vulns):
    print("TOOL CALLED: map_vulnerabilities_to_cwe")
    results = []
    print(vulns)
    retriever = get_store().as_retriever(search_kwargs={'k': 3})
    for vuln in vulns:
        print('VULNERABILITY')
        print(vuln)
        docs = retriever.invoke(vuln)
        if not docs:
            continue
        best = docs[0]
        results.append({
            "input_vulnerability": vuln,
            "cwe_id": best.metadata.get("cweID"),
            "cwe_name": best.metadata.get("name"),
            "description": best.page_content,
            "mitigations": best.metadata.get("potential_mitigations", [])
        })

    return results
