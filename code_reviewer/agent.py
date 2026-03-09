from dotenv import load_dotenv
from pydantic import BaseModel
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from langchain.agents import create_tool_calling_agent, AgentExecutor

# Custom tools that we will use. These are pulled from our tools.py
from tools import code_review

load_dotenv()

class AgentResponse(BaseModel):
    ...

llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash")
prompt = ChatPromptTemplate.from_messages([("system", """You're professional code reviewer. You have to highlight every antipattern or bug you find. If code clean you must say exactly 'no bugs'.""")])



