from fastapi import FastAPI
import uvicorn
from typing import Dict
from app.api.routers import main_router


app = FastAPI()


@app.get('/', response_model=Dict[str, str])
async def root():
    return {'message': 'agent'}


app.include_router(main_router)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
