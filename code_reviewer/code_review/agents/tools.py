import os
import requests
from qdrant_client.models import Filter, FieldCondition, MatchAny
from langchain.tools import tool
from langchain_qdrant import QdrantVectorStore
from dotenv import load_dotenv

from agents.preprocessing import run_dependency_check
from shared.store import COLLECTION_NAME, get_store


load_dotenv()


@tool('investigate_dependency_vulnerabilities', description='''
        Use this tool to check project dependencies for known security vulnerabilities.
        It returns verified CWE data from authoritative sources.
        Call this tool when you need to identify vulnerabilities in third-party libraries.
        Do not use it for analyzing custom code.'''
)
def dependency_vulnerability_analysis(_: str = ""):
    print("TOOL CALLED: investigate_vulnerabilities")
    print()
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

    clean_results = []
    for r in results:
        print(r)
        payload = r.payload or {}
        clean_results.append(payload)
    print(clean_results)
    return clean_results


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
    retriever = get_store().as_retriever(search_kwargs={'k': 3})
    for vuln in vulns:
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


GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ORCHESTRATION_URL = os.getenv("ORCHESTRATION_URL", "http://44.208.103.127:8000")
GITHUB_API_URL = "https://api.github.com"


def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True
    hash_obj = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256,
    )
    expected_signature = f"sha256={hash_obj.hexdigest()}"
    return hmac.compare_digest(expected_signature, signature_header)

@tool('accept_pr', description='''
        Use this tool to merge a pull request that has passed security analysis.
        It will merge the PR using GitHub's API and return the merge status.
        Call this tool when you need to merge a PR after confirming security checks are complete.
        Do not use this tool if security analysis has not been performed or has failed.'''
)
def accept_pr(repo_full_name: str, pr_number: int, merge_method: str = "merge") -> dict:
    if merge_method not in ('merge', 'squash', 'rebase'):
        raise ValueError('merge_method must be "merge", "squash", or "rebase"')
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable not set")
    
    # Split repo_full_name into owner/repo
    owner, repo = repo_full_name.split("/", 1)
    
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/merge"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {"merge_method": merge_method}

    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"success": False, "error": str(e)}


@tool('send_pr_notification', description='''Use this tool to send message about merged pull request to the messanger app. Pass message as a parameter.''')
def send_pr_notification(message: str = ""):
    print('send pr message tool was called')
    slack_app_token = os.getenv("SLACK_BOT_TOKEN", "")
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {slack_app_token}",
        "Content-Type": "application/json"
    }
    channel = os.getenv("SLACK_CHANNEL", "")
    payload = {
        "channel": channel,
        "text": message
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        print('aparently, message was sent')
        print(f'message sent: {message}')
        response.raise_for_status()

        return response.json()
    except Exception as e:
        return f"Error sending pr notification: {e}"

