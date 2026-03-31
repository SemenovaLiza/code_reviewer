from fastapi import APIRouter
from typing import Dict

from app.models.agent import CodeRequest
from agents.agent import security_agent


agent_router = APIRouter()


@agent_router.post('/security-agent/')
def chat_security_agent(data: CodeRequest):
    response = security_agent(data.code)
    return response
