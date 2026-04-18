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


@tool('accept_pr', description='''
        Use this tool to merge a pull request that has passed security analysis.
        It will merge the PR using GitHub's API and return the merge status.
        Call this tool when you need to merge a PR after confirming security checks are complete.
        Do not use this tool if security analysis has not been performed or has failed.'''
)
def accept_pr(pr_number):
    """
    Tool to automatically merge a pull request
    
    Args:
        pr_number: The PR number to merge (can be string like "123" or "#123")
    """
    print(f"TOOL CALLED: accept_pr - Merging PR #{pr_number}")
    print()
    
    clean_pr = str(pr_number).replace("#", "").strip()
    
    github_token = os.getenv('GITHUB_TOKEN')
    repo_owner = os.getenv('GITHUB_REPO_OWNER')
    repo_name = os.getenv('GITHUB_REPO_NAME')
    
    if not all([github_token, repo_owner, repo_name]):
        return {
            "success": False,
            "error": "Missing GitHub configuration. Check environment variables."
        }
    
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{clean_pr}/merge"
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    try:
        response = requests.put(url, headers=headers, json={"merge_method": "merge"})
        
        if response.status_code == 200:
            result = {
                "success": True,
                "message": f"PR #{clean_pr} successfully merged",
                "sha": response.json().get('sha')
            }
            print(f"✓ {result['message']}")
        else:
            result = {
                "success": False,
                "error": f"Failed to merge: {response.json().get('message', 'Unknown error')}"
            }
            print(f"✗ {result['error']}")
            
        return result
        
    except Exception as e:
        error_result = {"success": False, "error": str(e)}
        print(f"✗ Error: {str(e)}")
        return error_result


@tool('send_notification', description='''
        Use this tool to send notifications about PR merges to a Slack channel.
        It sends formatted messages to notify the team about PR status changes.
        Call this tool after successfully merging a PR or when there are issues with the merge.
        Do not use this tool for non-PR related notifications.'''
)
def send_notification(message):
    """
    Tool to send notifications to Slack
    
    Args:
        message: The message to send to Slack
    """
    print(f"TOOL CALLED: send_slack_notification")
    print(f"Message: {message}")
    print()
    
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    
    if not webhook_url:
        print("✗ Slack webhook URL not configured")
        return {
            "success": False,
            "error": "Slack webhook URL not configured"
        }
    
    payload = {
        "text": message
    }
    
    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            result = {"success": True, "message": "Notification sent to Slack"}
            print(f"✓ {result['message']}")
        else:
            result = {"success": False, "error": f"Slack API error: {response.text}"}
            print(f"✗ {result['error']}")
            
        return result
        
    except Exception as e:
        error_result = {"success": False, "error": str(e)}
        print(f"✗ Error: {str(e)}")
        return error_result