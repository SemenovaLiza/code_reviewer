from fastapi import APIRouter, Request
from typing import Dict, List
import json

from app.models.agent import CodeRequest, OrchestrationRequest, OrchestrationResponse
from agents.agent import CodeVulnerability, DependencyVulnerability


agent_router = APIRouter()


# @agent_router.post('/security-agent/')
# def chat_security_agent(data: CodeRequest):
#     agent = request.app.state.security_agent
#     response = agent.invoke({'messages': [{'role': 'user', 'content': data.code}]})
#     print('agent response')
#     print(response)
#     return response

async def security_agent(request: Request, data):
    agent = request.app.state.security_agent
    response = await agent.ainvoke({'messages': [{'role': 'user', 'content': data}]})
    print(response)
    return response


async def pr_manager_agent(request: Request, data):
    agent = request.app.state.pr_manager_agent
    response = await agent.ainvoke(data)
    print(response)
    return response


def has_vulnerabilities(agent_response: dict) -> bool:
    """Return True if the agent found at least one vulnerability."""
    return bool(
        agent_response.code_analysis or
        agent_response.dependencies_analysis
    )

def parse_code_vulns(raw: list) -> List[CodeVulnerability]:
    return [
        CodeVulnerability(
            file=v.file,
            line=v.line,
            severity=v.severity,
            cwe_id=v.cwe_id,
            cwe_name=v.cwe_name,
            why_dangerous=v.why_dangerous,
            affected_code=v.affected_code,
            mitigations=v.mitigations,
            agent=v.agent,
            suppressed=v.suppressed
        )
        for v in raw
    ]


def parse_dep_vulns(raw: list) -> List[DependencyVulnerability]:
    return [
        DependencyVulnerability(
            dependency=v.dependency,
            version=v.version,
            severity=v.severity,
            cwe_id=v.cwe_id,
            cwe_name=v.cwe_name,
            why_dangerous=v.why_dangerous,
            mitigations=v.mitigations,
        )
        for v in raw
    ]


async def security_review(data: CodeRequest, request: Request):
    """
    Orchestration workflow:
      1. Call the security agent with the provided code.
      2. If NO vulnerabilities found → return status "all_good".
      3. If vulnerabilities found    → return status "vulnerabilities_found"
         with the full parsed results for the webhook to format and post.
    """
    agent_response = await security_agent(request, data.code)
    
    if not has_vulnerabilities(agent_response):
        print('merge sent')
        merge_response = await pr_manager_agent(request, json.dumps({"merge": True, "repo_full_name": data.repo_full_name, "pr_number": data.pr_number}))
        return OrchestrationResponse(
            status="all_good",
            message=f"No vulnerabilities detected in code or dependencies. Merger response: {merge_response}",
        )

    return OrchestrationResponse(
        status="vulnerabilities_found",
        message="Security vulnerabilities were detected. See code_analysis and dependencies_analysis for details.",
        code_analysis=parse_code_vulns(agent_response.code_analysis),
        dependencies_analysis=parse_dep_vulns(agent_response.dependencies_analysis),
    )


@agent_router.post("/orchestrate/security-review", response_model=OrchestrationResponse)
async def orchestrate_pr(data: CodeRequest, request: Request):
    response = await security_review(data, request)
    print('ORCH!')
    print(response)
    return response
