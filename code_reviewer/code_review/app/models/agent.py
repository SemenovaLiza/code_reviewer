from pydantic import BaseModel
from typing import List

from agents.agent import CodeVulnerability, DependencyVulnerability


class CodeRequest(BaseModel):
    code:str
    repo_full_name:str
    pr_number:int


class OrchestrationRequest(BaseModel):
    code: str


class OrchestrationResponse(BaseModel):
    status: str
    message: str
    code_analysis: List[CodeVulnerability] = []
    dependencies_analysis: List[DependencyVulnerability] = []
