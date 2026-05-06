from fastapi import FastAPI
import uvicorn
from typing import Dict
from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.api.routers import main_router
from agents.agent import build_security_agent, build_pr_manager_agent


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.security_agent = build_security_agent()
    app.state.pr_manager_agent = build_pr_manager_agent()
    yield

app = FastAPI(lifespan=lifespan)


@app.get('/', response_model=Dict[str, str])
async def root():
    return {'message': 'agent'}


app.include_router(main_router)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
