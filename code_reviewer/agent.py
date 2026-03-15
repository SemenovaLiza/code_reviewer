from dotenv import load_dotenv
from transformers import pipeline
# Custom tools that we will use. These are pulled from our tools.py
from tools import code_review

load_dotenv()

pipe = pipeline("text-generation", model="openai-community/gpt2")

response = pipe("text")