from fastapi import APIRouter
from typing import Dict

from app.models.agent import CodeRequest
from agents.agent import security_agent
from agents.orchestrator import orchestrator


agent_router = APIRouter()


@agent_router.post('/security-agent/')
def chat_security_agent(data: CodeRequest):
    response = security_agent(data.code)
    print('agent response')
    print(response)
    return response


@agent_router.post('/orchestrate_pr/')
def orchestrate_pr(data: CodeRequest):
    response = orchestrator(data.code)
    print('ORCH!')
    print(response)
    return response
