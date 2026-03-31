import os
from typing import List
from dotenv import load_dotenv
from dataclasses import dataclass
from langchain.agents import create_agent
from langchain.tools import tool,ToolRuntime
from langchain_core.prompts import ChatPromptTemplate
from langchain.chat_models import init_chat_model
from langgraph.checkpoint.memory import InMemorySaver # remembering the messages

from agents.system_instructions import instructions
#from input import user_code
from agents.embeddings import get_context


load_dotenv()


config = {'configurable': {'thread_id': 1}}


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


def security_agent(message):
    agent = create_agent(
        model = 'mistral-small-2603',
        tools = [get_context()],
        system_prompt = instructions['security_analyst'],
        context_schema = SecurityContext,
        response_format = SecurityResponse,
        checkpointer = checkpointer
    )
    response = agent.invoke(
        {
            'messages': [{
                'role': 'user', 'content': message  
            }]
        },
        config = config,
        context = Context(location=os.path.dirname(os.path.abspath(__file__)))
    )
    return response['structured_response']


def static_agent(message):
    agent = create_agent(
        model = 'mistral-small-2603',
        tools = [],
        system_prompt = instructions['static_analyst'],
        response_format=StaticAnalysesResponse
    )
    response = agent.invoke(
        {
            'messages': [{
                'role': 'user', 'content': message  
            }]
        },
        config = config,
        context = Context(location=os.path.dirname(os.path.abspath(__file__)))
    )
    return response['structured_response']
