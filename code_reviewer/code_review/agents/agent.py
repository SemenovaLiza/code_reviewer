import os
from typing import List
from dotenv import load_dotenv
from dataclasses import dataclass
from langchain.agents import create_agent
# from langgraph.checkpoint.memory import InMemorySaver # remembering messages

from agents.system_instructions import instructions
from agents.tools import map_vulnerabilities_to_cwe, dependency_vulnerability_analysis, accept_pr, send_pr_notification


load_dotenv()


config = {'configurable': {'thread_id': 1}}


@dataclass
class CodeVulnerability:
    agent: str
    file: str
    line: int
    severity: str
    cwe_id: str
    cwe_name: str
    affected_code: str
    why_dangerous: str
    mitigations: List[str]
    suppressed: bool


@dataclass
class DependencyVulnerability:
    agent: str
    dependency: str
    version: str
    severity: str
    cwe_id: str
    cwe_name: str
    why_dangerous: str
    mitigations: List[str]
    suppressed: bool


@dataclass
class SecurityResponse:
    code_analysis: List[CodeVulnerability]
    dependencies_analysis: List[DependencyVulnerability]    


@dataclass
class PRMessage():
    pr_id: int
    mesaage: str


@dataclass
class PRManagerResponse():
    message: PRMessage


#checkpointer = InMemorySaver()


def security_agent(message):
    agent = create_agent(
        model = 'mistral-small-2603',
        tools = [map_vulnerabilities_to_cwe, dependency_vulnerability_analysis],
        system_prompt = instructions['security_analyst'],
        response_format = SecurityResponse
        #checkpointer = checkpointer
    )
    response = agent.invoke(
        {
            'messages': [{
                'role': 'user', 'content': message  
            }]
        },
        #config = config,
    )
    return response['structured_response']


def pr_manager_agent(message):
    agent = create_agent(
        model = 'mistral-small-2603',
        tools = [accept_pr, send_pr_notification],
        system_prompt = instructions['merge_agent'],
        response_format = PRManagerResponse
    )
    response = agent.invoke(
        {
            'messages': [{
                'role': 'user', 'content': message  
            }]
        },
        #config = config,
    )
    return response['structured_response']
