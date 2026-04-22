import os
import hmac
import hashlib
import json
import base64
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
import httpx
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Environment variables
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


async def fetch_pr_diff(repo_full_name: str, pr_number: int) -> str:
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.text


async def fetch_pr_files(repo_full_name: str, pr_number: int) -> List[Dict]:
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


async def post_pr_comment(repo_full_name: str, pr_number: int, comment_body: str):
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json={"body": comment_body})
        response.raise_for_status()
        return response.json()


async def post_review_comment(
    repo_full_name: str,
    pr_number: int,
    commit_id: str,
    file_path: str,
    line: int,
    comment_body: str,
):
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "body": comment_body,
        "commit_id": commit_id,
        "path": file_path,
        "line": line,
        "side": "RIGHT",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()


def format_security_response(result) -> str:
    print('RESPONSE FOR FINAL!!!')
    print(result, type(result))
    if not result['code_analysis'] and not result['dependencies_analysis']:
        return "## 🔒 Security Analysis Results\n\n✅ No vulnerabilities detected! Good work!"

    parts = ["## 🔒 Security Analysis Results\n"]

    if result['code_analysis']:
        parts.append("### 🚨 Code Vulnerabilities Found\n")
        for vuln in result['code_analysis']:
            parts.append(f"#### 📍 `{vuln['file']}` (Line {vuln['line']})")
            parts.append(f"**Severity:** `{vuln['severity'].upper()}`")
            parts.append(f"**CWE:** {vuln['cwe_id']} - {vuln['cwe_name']}")
            parts.append(f"**Issue:** {vuln['why_dangerous']}")
            parts.append(f"**Affected Code:**\n```python\n{vuln['affected_code']}\n```")
            parts.append("**Mitigations:**")
            for m in vuln['mitigations']:
                parts.append(f"- {m}")
            parts.append("")

    if result['dependencies_analysis']:
        parts.append("### 📦 Dependency Vulnerabilities\n")
        for vuln in result['dependencies_analysis']:
            parts.append(f"#### {vuln['dependency']}@{vuln['version']}")
            parts.append(f"**Severity:** `{vuln['severity'].upper()}`")
            parts.append(f"**CWE:** {vuln['cwe_id']} - {vuln['cwe_name']}")
            parts.append(f"**Issue:** {vuln['why_dangerous']}")
            parts.append("**Mitigations:**")
            for m in vuln['mitigations']:
                parts.append(f"- {m}")
            parts.append("")

    return "\n".join(parts)


def prepare_agent_input(pr_info: Dict[str, Any], diff_content: str, changed_files: List[Dict]) -> str:
    files_list = "\n".join([f"- {f['filename']}" for f in changed_files[:20]])
    return f"Changed Files:\n{files_list}\n\nCode Changes (Diff):\n{diff_content[:15000]}"


async def call_orchestration_layer(code: str):
    """Send code to the orchestration layer and return a typed response."""
    async with httpx.AsyncClient(timeout=90.0) as client:
        response = await client.post(
            f"{ORCHESTRATION_URL}/orchestrate/security-review",
            json={"code": code},
        )
        response.raise_for_status()
        print('RESPONSE!')
        print(response)
        return response.json()



async def process_pr_webhook(payload: Dict[str, Any]):
    try:
        action = payload.get("action")
        if action not in ("opened", "synchronize", "reopened"):
            print(f"Ignoring action: {action}")
            return

        pr = payload.get("pull_request", {})
        repo_full_name = payload.get("repository", {}).get("full_name")
        pr_number = pr.get("number")
        pr_head_sha = pr.get("head", {}).get("sha")

        print(f"Processing PR #{pr_number} in {repo_full_name} (action: {action})")

        # Let the author know analysis has started
        await post_pr_comment(
            repo_full_name,
            pr_number,
            "🔍 **Security Analysis Started**\n\nAnalyzing your PR for vulnerabilities — hang tight...",
        )

        # Gather diff + file list
        diff_content = await fetch_pr_diff(repo_full_name, pr_number)
        changed_files = await fetch_pr_files(repo_full_name, pr_number)
        code_payload = prepare_agent_input(pr, diff_content, changed_files)

        print("Calling orchestration layer...")
        print(payload)
        result = await call_orchestration_layer(code_payload)

        if result['status'] == "all_good":
            await post_pr_comment(
                repo_full_name,
                pr_number,
                "## 🔒 Security Analysis Results\n\n✅ No vulnerabilities detected! Good work!",
            )
            print(f"PR #{pr_number}: no vulnerabilities found — posted all-clear.")
            return

        # Vulnerabilities found — post inline comments first
        for vuln in result['code_analysis']:
            try:
                await post_review_comment(
                    repo_full_name,
                    pr_number,
                    pr_head_sha,
                    vuln['file'],
                    vuln['line'],
                    (
                        f"🔒 **Security Issue**\n\n"
                        f"**Severity:** {vuln['severity'].upper()}\n"
                        f"**CWE:** {vuln['cwe_name']}\n"
                        f"**Why dangerous:** {vuln['why_dangerous']}\n\n"
                        f"**Mitigation:** {vuln['mitigations'][0] if vuln['mitigations'] else 'Review the code carefully'}"
                    ),
                )
            except Exception as e:
                print(f"Failed to post inline comment for {vuln['file']}:{vuln['line']} — {e}")

        # Post summary comment
        await post_pr_comment(repo_full_name, pr_number, format_security_response(result))
        print(f"PR #{pr_number}: security analysis posted successfully.")

    except Exception as e:
        print(f"Error processing PR webhook: {e}")
        try:
            repo_name = payload.get("repository", {}).get("full_name")
            pr_num = payload.get("pull_request", {}).get("number")
            if repo_name and pr_num:
                await post_pr_comment(
                    repo_name,
                    pr_num,
                    f"❌ **Error during security analysis**\n\n```\n{str(e)[:500]}\n```",
                )
        except Exception:
            pass


@app.post("/webhook/github/pr")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()

    if not verify_github_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event_type = request.headers.get("X-GitHub-Event")
    if event_type != "pull_request":
        return JSONResponse(content={"message": f"Ignoring event type: {event_type}"})

    payload = await request.json()
    background_tasks.add_task(process_pr_webhook, payload)
    return JSONResponse(content={"message": "Webhook received, processing in background"})


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
