# webhook_server.py
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
SECURITY_AGENT_URL = os.getenv("SECURITY_AGENT_URL", "http://3.88.187.32:8000")
GITHUB_API_URL = "https://api.github.com"

# Pydantic models for type safety (no agent imports needed)
class CodeVulnerability(BaseModel):
    file: str
    line: int
    severity: str
    cwe_id: str
    cwe_name: str
    why_dangerous: str
    affected_code: str
    mitigations: List[str]

class DependencyVulnerability(BaseModel):
    dependency: str
    version: str
    severity: str
    cwe_id: str
    cwe_name: str
    why_dangerous: str
    mitigations: List[str]

class SecurityResponse(BaseModel):
    code_analysis: List[CodeVulnerability] = []
    dependencies_analysis: List[DependencyVulnerability] = []


def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify webhook signature for security"""
    if not GITHUB_WEBHOOK_SECRET:
        return True  # Skip verification if no secret set (development only)
    
    hash_obj = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = f"sha256={hash_obj.hexdigest()}"
    return hmac.compare_digest(expected_signature, signature_header)


async def fetch_pr_diff(repo_full_name: str, pr_number: int) -> str:
    """Fetch PR diff using GitHub API"""
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.text


async def fetch_pr_files(repo_full_name: str, pr_number: int) -> List[Dict]:
    """Fetch list of changed files in PR"""
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


async def fetch_file_content(repo_full_name: str, file_path: str, ref: str) -> str:
    """Fetch content of a specific file from the repo"""
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/contents/{file_path}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    params = {"ref": ref}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers, params=params)
        if response.status_code == 200:
            content = response.json()
            if 'content' in content:
                return base64.b64decode(content['content']).decode('utf-8')
        return ""


async def post_pr_comment(repo_full_name: str, pr_number: int, comment_body: str):
    """Post a comment to the PR"""
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    payload = {"body": comment_body}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()


async def post_review_comment(repo_full_name: str, pr_number: int, commit_id: str, 
                              file_path: str, line: int, comment_body: str):
    """Post an inline review comment on a specific line"""
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    payload = {
        "body": comment_body,
        "commit_id": commit_id,
        "path": file_path,
        "line": line,
        "side": "RIGHT"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()


def format_security_response(security_result: SecurityResponse) -> str:
    """Format SecurityResponse into a readable GitHub comment"""
    if not security_result.code_analysis and not security_result.dependencies_analysis:
        return "## 🔒 Security Analysis Results\n\n✅ No vulnerabilities detected! Good work!"
    
    comment_parts = ["## 🔒 Security Analysis Results\n"]
    
    # Format code vulnerabilities
    if security_result.code_analysis:
        comment_parts.append("### 🚨 Code Vulnerabilities Found\n")
        for vuln in security_result.code_analysis:
            comment_parts.append(f"#### 📍 `{vuln.file}` (Line {vuln.line})")
            comment_parts.append(f"**Severity:** `{vuln.severity.upper()}`")
            comment_parts.append(f"**CWE:** {vuln.cwe_id} - {vuln.cwe_name}")
            comment_parts.append(f"**Issue:** {vuln.why_dangerous}")
            comment_parts.append(f"**Affected Code:**\n```python\n{vuln.affected_code}\n```")
            comment_parts.append("**Mitigations:**")
            for mitigation in vuln.mitigations:
                comment_parts.append(f"- {mitigation}")
            comment_parts.append("")
    
    # Format dependency vulnerabilities
    if security_result.dependencies_analysis:
        comment_parts.append("### 📦 Dependency Vulnerabilities\n")
        for vuln in security_result.dependencies_analysis:
            comment_parts.append(f"#### {vuln.dependency}@{vuln.version}")
            comment_parts.append(f"**Severity:** `{vuln.severity.upper()}`")
            comment_parts.append(f"**CWE:** {vuln.cwe_id} - {vuln.cwe_name}")
            comment_parts.append(f"**Issue:** {vuln.why_dangerous}")
            comment_parts.append("**Mitigations:**")
            for mitigation in vuln.mitigations:
                comment_parts.append(f"- {mitigation}")
            comment_parts.append("")
    
    return "\n".join(comment_parts)


def prepare_agent_input(pr_info: Dict[str, Any], diff_content: str, changed_files: List[Dict]) -> Dict[str, str]:
    """Prepare the message for your security agent"""
    # Get list of changed files
    files_list = "\n".join([f"- {f['filename']}" for f in changed_files[:20]])
    
    # Prepare the message for the agent
    message = f"""
Changed Files:
{files_list}

Code Changes (Diff):
{diff_content[:15000]}
    """
    
    return {"code": message}


async def call_security_agent(agent_input: Dict[str, str]) -> SecurityResponse:
    """Call the security agent API - no direct imports needed"""
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{SECURITY_AGENT_URL}/security-agent/",
            json=agent_input
        )
        response.raise_for_status()
        
        # Parse the JSON response into our local model
        data = response.json()
        
        # Convert code_analysis
        code_analysis = []
        for vuln_data in data.get('code_analysis', []):
            code_analysis.append(CodeVulnerability(
                file=vuln_data.get('file', ''),
                line=vuln_data.get('line', 0),
                severity=vuln_data.get('severity', ''),
                cwe_id=vuln_data.get('cwe_id', ''),
                cwe_name=vuln_data.get('cwe_name', ''),
                why_dangerous=vuln_data.get('why_dangerous', ''),
                affected_code=vuln_data.get('affected_code', ''),
                mitigations=vuln_data.get('mitigations', [])
            ))
        
        # Convert dependencies_analysis
        deps_analysis = []
        for vuln_data in data.get('dependencies_analysis', []):
            deps_analysis.append(DependencyVulnerability(
                dependency=vuln_data.get('dependency', ''),
                version=vuln_data.get('version', ''),
                severity=vuln_data.get('severity', ''),
                cwe_id=vuln_data.get('cwe_id', ''),
                cwe_name=vuln_data.get('cwe_name', ''),
                why_dangerous=vuln_data.get('why_dangerous', ''),
                mitigations=vuln_data.get('mitigations', [])
            ))
        
        return SecurityResponse(
            code_analysis=code_analysis,
            dependencies_analysis=deps_analysis
        )


async def process_pr_webhook(payload: Dict[str, Any]):
    """Main function to process PR webhook and trigger security agent"""
    try:
        pr = payload.get("pull_request", {})
        action = payload.get("action")
        
        # Only process relevant actions
        if action not in ["opened", "synchronize", "reopened"]:
            print(f"Ignoring action: {action}")
            return
        
        repo_full_name = payload.get("repository", {}).get("full_name")
        pr_number = pr.get("number")
        pr_head_sha = pr.get("head", {}).get("sha")
        
        print(f"Processing PR #{pr_number} in {repo_full_name} (Action: {action})")
        
        # Send initial comment that analysis started
        await post_pr_comment(
            repo_full_name, 
            pr_number, 
            "🔍 **Security Analysis Started**\n\nI'm analyzing your PR for security vulnerabilities. This may take a moment..."
        )
        
        # Fetch PR diff and changed files
        diff_content = await fetch_pr_diff(repo_full_name, pr_number)
        changed_files = await fetch_pr_files(repo_full_name, pr_number)
        
        # Prepare input for security agent
        agent_input = prepare_agent_input(pr, diff_content, changed_files)
        
        # Run your security agent via HTTP
        print("Calling security agent...")
        # security_result = await call_security_agent(agent_input)
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{SECURITY_AGENT_URL}/orchestrate_pr/",
                json=agent_input
            )
            response.raise_for_status()
            
            # Parse the JSON response into our local model
            data = response.json()
        # Format and post results
        # formatted_comment = format_security_response(security_result)
        
        # # Also post inline comments for specific vulnerabilities
        # if security_result.code_analysis:
        #     for vuln in security_result.code_analysis:
        #         try:
        #             await post_review_comment(
        #                 repo_full_name,
        #                 pr_number,
        #                 pr_head_sha,
        #                 vuln.file,
        #                 vuln.line,
        #                 f"🔒 **Security Issue**\n\n**Severity:** {vuln.severity.upper()}\n**CWE:** {vuln.cwe_name}\n**Why dangerous:** {vuln.why_dangerous}\n\n**Mitigation:** {vuln.mitigations[0] if vuln.mitigations else 'Review the code carefully'}"
        #             )
        #         except Exception as e:
        #             print(f"Failed to post inline comment for {vuln.file}:{vuln.line} - {e}")
        
        # # Post the summary comment
        # await post_pr_comment(repo_full_name, pr_number, formatted_comment)
        
        # print(f"Successfully posted security analysis for PR #{pr_number}")
        
    except Exception as e:
        print(f"Error processing PR webhook: {str(e)}")
        # Post error comment
        try:
            repo_name = payload.get("repository", {}).get("full_name")
            pr_num = payload.get("pull_request", {}).get("number")
            if repo_name and pr_num:
                await post_pr_comment(
                    repo_name,
                    pr_num,
                    f"❌ **Error during security analysis**\n\n```\n{str(e)[:500]}\n```"
                )
        except:
            pass


@app.post("/webhook/github/pr")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle GitHub PR webhook"""
    # Verify signature
    signature = request.headers.get("X-Hub-Signature-256")
    body = await request.body()
    
    if not verify_github_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Get event type
    event_type = request.headers.get("X-GitHub-Event")
    if event_type != "pull_request":
        return JSONResponse(content={"message": f"Ignoring event type: {event_type}"})
    
    # Parse payload
    payload = await request.json()
    
    # Process in background to avoid webhook timeout
    background_tasks.add_task(process_pr_webhook, payload)
    
    return JSONResponse(content={"message": "Webhook received, processing in background"})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
