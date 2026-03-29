import os
from typing import List
from dotenv import load_dotenv
from dataclasses import dataclass
from langchain.agents import create_agent
from langchain.tools import tool,ToolRuntime
from langchain_core.prompts import ChatPromptTemplate
from langchain.chat_models import init_chat_model
from langgraph.checkpoint.memory import InMemorySaver # remembering the messages

from system_instructions import instructions
from input import user_code


load_dotenv()


@dataclass
class Context:
    location: str # location of reviewed file


@dataclass
class ResponseFormat:
    agent: str
    file: str
    line: int
    severity: str
    rule_id: str
    message: str
    suggestion: str


@dataclass
class SecurityContext:
    location: str # location of reviewed file
    vulnerabilities: list[str]
    insecure_dependencies: list[str]
    unsafe_patters: list[str]


@dataclass
class SecurityExtendedResponse(ResponseFormat):
    cve: str
    attack_vector: str


@dataclass
class SecurityResponse():
    message: List[SecurityExtendedResponse]
    

@dataclass
class StaticAnalysesResponse():
    message: List[ResponseFormat]


checkpointer = InMemorySaver()
 

@tool('investigate_vulnerabilities', description='Semgrep cli tool for code vulnerabiltiies lookup.')
def get_vulnerabilities(code: str):
    ...

security_agent = create_agent(
    model = 'mistral-small-2603',
    tools = [],
    system_prompt = instructions['security_analyst'],
    context_schema = SecurityContext,
    response_format = SecurityResponse,
    checkpointer = checkpointer
)

static_analyst_agent = create_agent(
    model = 'mistral-small-2603',
    tools = [],
    system_prompt = instructions['static_analyst'],
    response_format=StaticAnalysesResponse
)


config = {'configurable': {'thread_id': 1}}\

def static_analyst_agent(input: str):
    response = static_analyst_agent.invoke(
        {
            'messages': [{
                'role': 'user', 'content': user_code  
            }]
        }
    )
    return response['structured_response']


def security_analyst_agent(input: str):
    response = security_agent.invoke(
        {
            'messages': [{
                'role': 'user', 'content': user_code  
            }]
        },
        config = config,
        context = Context(location=os.path.dirname(os.path.abspath(__file__)))
    )
    return response['structured_response']
