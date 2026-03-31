from fastapi import APIRouter

from app.api.endpoints import agent_router


main_router = APIRouter()
main_router.include_router(agent_router)