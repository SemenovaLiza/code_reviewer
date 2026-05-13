import os
from fastapi import FastAPI
import uvicorn
from typing import Dict
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from fastapi import FastAPI
from langchain_mcp_adapters.client import MultiServerMCPClient 

from app.api.routers import main_router
from agents.agent import build_security_agent, build_pr_manager_agent

load_dotenv()

MCP_BASE_URL = os.getenv('MCP_BASE_URL')
MANAGER_PORT = os.getenv('MANAGER_PORT')
SECURITY_PORT = os.getenv('SECURITY_PORT')

MCP_SERVERS_ = {
    'security': {"url": f"{MCP_BASE_URL}:{SECURITY_PORT}/sse", "transport": "sse"},
    'manager': {"url": f"{MCP_BASE_URL}:{MANAGER_PORT}/sse", "transport": "sse"},
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    security_client = MultiServerMCPClient({'security': MCP_SERVERS_['security']})
    manager_client = MultiServerMCPClient({'manager': MCP_SERVERS_['manager']})
    security_tools = await security_client.get_tools()
    manager_tools = await manager_client.get_tools()

    app.state.security_agent = build_security_agent(security_tools)
    app.state.manager_agent = build_pr_manager_agent(manager_tools)
    
    for tool in security_tools:
        tool.response_format == "content"

    for tool in manager_tools:
        tool.response_format == "content"
    yield

app = FastAPI(lifespan=lifespan)


@app.get('/', response_model=Dict[str, str])
async def root():
    return {'message': 'agent'}


app.include_router(main_router)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
