from fastapi import APIRouter
from typing import Dict, List

from app.models.agent import CodeRequest, OrchestrationRequest, OrchestrationResponse
from agents.agent import security_agent, CodeVulnerability, DependencyVulnerability
from agents.orchestrator import orchestrator


agent_router = APIRouter()


@agent_router.post('/security-agent/')
def chat_security_agent(data: CodeRequest):
    response = security_agent(data.code)
    print('agent response')
    print(response)
    return response


def has_vulnerabilities(agent_response: dict) -> bool:
    """Return True if the agent found at least one vulnerability."""
    return bool(
        agent_response.get("code_analysis") or
        agent_response.get("dependencies_analysis")
    )

def parse_code_vulns(raw: list) -> List[CodeVulnerability]:
    return [
        CodeVulnerability(
            file=v.get("file", ""),
            line=v.get("line", 0),
            severity=v.get("severity", ""),
            cwe_id=v.get("cwe_id", ""),
            cwe_name=v.get("cwe_name", ""),
            why_dangerous=v.get("why_dangerous", ""),
            affected_code=v.get("affected_code", ""),
            mitigations=v.get("mitigations", []),
        )
        for v in raw
    ]


def parse_dep_vulns(raw: list) -> List[DependencyVulnerability]:
    return [
        DependencyVulnerability(
            dependency=v.get("dependency", ""),
            version=v.get("version", ""),
            severity=v.get("severity", ""),
            cwe_id=v.get("cwe_id", ""),
            cwe_name=v.get("cwe_name", ""),
            why_dangerous=v.get("why_dangerous", ""),
            mitigations=v.get("mitigations", []),
        )
        for v in raw
    ]


async def security_review(request: OrchestrationRequest):
    """
    Orchestration workflow:
      1. Call the security agent with the provided code.
      2. If NO vulnerabilities found → return status "all_good".
      3. If vulnerabilities found    → return status "vulnerabilities_found"
         with the full parsed results for the webhook to format and post.
    """
    agent_response = security_agent(request.code)
    
    if not has_vulnerabilities(agent_response):
        return OrchestrationResponse(
            status="all_good",
            message="No vulnerabilities detected in code or dependencies.",
        )

    return OrchestrationResponse(
        status="vulnerabilities_found",
        message="Security vulnerabilities were detected. See code_analysis and dependencies_analysis for details.",
        code_analysis=parse_code_vulns(agent_response.get("code_analysis", [])),
        dependencies_analysis=parse_dep_vulns(agent_response.get("dependencies_analysis", [])),
    )


@agent_router.post("/orchestrate/security-review", response_model=OrchestrationResponse)
def orchestrate_pr(data: CodeRequest):
    response = orchestrator(data.code)
    print('ORCH!')
    print(response)
    return response
